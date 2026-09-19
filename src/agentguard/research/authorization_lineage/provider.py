from __future__ import annotations

import hashlib
import multiprocessing
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from multiprocessing.connection import Connection
from pathlib import Path
from typing import Iterator
from uuid import uuid4

from .models import ProviderEvidence, ProviderStratum


def _sha256(value: str) -> str:
    return "sha256:" + hashlib.sha256(value.encode()).hexdigest()


class OracleIsolationError(RuntimeError):
    pass


@contextmanager
def _sqlite_connection(
    path: Path, *, timeout: float = 5.0
) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(path, timeout=timeout)
    try:
        with connection:
            yield connection
    finally:
        connection.close()


_ORACLE_SCHEMA = """
CREATE TABLE IF NOT EXISTS effects(
    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    trial_id TEXT NOT NULL,
    effect_id TEXT NOT NULL UNIQUE,
    provider_stratum TEXT NOT NULL,
    attempt_id TEXT NOT NULL,
    logical_effect_key_digest TEXT NOT NULL,
    idempotency_key_digest TEXT,
    request_fingerprint TEXT NOT NULL,
    committed_at TEXT NOT NULL
);
"""


def _oracle_worker(path_text: str, receiver: Connection, ready_sender: Connection) -> None:
    """Separate-process ground-truth writer. It exposes no query channel."""

    path = Path(path_text)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with _sqlite_connection(path) as connection:
            connection.executescript(_ORACLE_SCHEMA)
        ready_sender.send("READY")
    except Exception as exc:
        try:
            ready_sender.send(f"ERROR:{type(exc).__name__}")
        finally:
            ready_sender.close()
            receiver.close()
        return
    ready_sender.close()
    try:
        while True:
            message = receiver.recv()
            if message is None:
                return
            if not isinstance(message, tuple) or len(message) != 8:
                raise OracleIsolationError("oracle.invalid_append_message")
            with _sqlite_connection(path) as connection:
                connection.execute(
                    """
                    INSERT INTO effects(
                        trial_id,effect_id,provider_stratum,attempt_id,logical_effect_key_digest,
                        idempotency_key_digest,request_fingerprint,committed_at
                    ) VALUES(?,?,?,?,?,?,?,?)
                    """,
                    message,
                )
    finally:
        receiver.close()


@dataclass(frozen=True)
class OracleAppendSink:
    """Write-only provider capability. It contains no oracle DB path and no read method."""

    _sender: Connection

    def append(
        self,
        *,
        trial_id: str,
        provider: ProviderStratum,
        attempt_id: str,
        effect_key: str,
        idempotency_key: str | None,
    ) -> str:
        effect_id = "effect_" + uuid4().hex
        request_fingerprint = _sha256(
            "|".join((trial_id, provider.value, attempt_id, effect_key, idempotency_key or ""))
        )
        try:
            self._sender.send(
                (
                    trial_id,
                    effect_id,
                    provider.value,
                    attempt_id,
                    _sha256(effect_key),
                    _sha256(idempotency_key) if idempotency_key is not None else None,
                    request_fingerprint,
                    datetime.now(UTC).isoformat(),
                )
            )
        except (BrokenPipeError, EOFError, OSError) as exc:
            raise OracleIsolationError("oracle.append_channel_failed") from exc
        return effect_id


class IndependentEffectOracleProcess:
    """Own the independent effect database in a dedicated spawned process."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        context = multiprocessing.get_context("spawn")
        receiver, sender = context.Pipe(duplex=False)
        ready_receiver, ready_sender = context.Pipe(duplex=False)
        self._sender = sender
        self._process = context.Process(
            target=_oracle_worker,
            args=(str(path), receiver, ready_sender),
            name="agentguard-research-effect-oracle",
            daemon=False,
        )
        self._process.start()
        receiver.close()
        ready_sender.close()
        try:
            if not ready_receiver.poll(10.0):
                self._terminate_startup_failure()
                raise OracleIsolationError("oracle.process_startup_timeout")
            message = ready_receiver.recv()
        except (EOFError, OSError) as exc:
            self._terminate_startup_failure()
            raise OracleIsolationError("oracle.process_startup_channel_failed") from exc
        finally:
            ready_receiver.close()
        if message != "READY" or not self._process.is_alive():
            self._terminate_startup_failure()
            raise OracleIsolationError(f"oracle.process_startup_failed:{message}")
        self.sink = OracleAppendSink(self._sender)
        self._closed = False

    def _terminate_startup_failure(self) -> None:
        try:
            self._sender.close()
        finally:
            if self._process.is_alive():
                self._process.terminate()
            self._process.join(timeout=2.0)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        send_error = False
        try:
            self._sender.send(None)
        except (BrokenPipeError, EOFError, OSError):
            send_error = True
        finally:
            self._sender.close()
        self._process.join(timeout=10.0)
        if self._process.is_alive():
            self._process.terminate()
            self._process.join(timeout=2.0)
            raise OracleIsolationError("oracle.process_shutdown_timeout")
        if self._process.exitcode != 0:
            raise OracleIsolationError(f"oracle.process_failed:{self._process.exitcode}")
        if send_error:
            raise OracleIsolationError("oracle.shutdown_channel_failed")


class IndependentEffectOracleReader:
    """Analysis-only reader. Never pass this object to a SUT or provider reconciler."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def effect_count(self, trial_id: str) -> int:
        with _sqlite_connection(self.path) as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM effects WHERE trial_id=?", (trial_id,)
            ).fetchone()
        return int(row[0]) if row is not None else 0

    def rows(self, trial_id: str) -> tuple[tuple[object, ...], ...]:
        with _sqlite_connection(self.path) as connection:
            rows = connection.execute(
                """
                SELECT sequence,effect_id,provider_stratum,attempt_id,
                       logical_effect_key_digest,idempotency_key_digest,request_fingerprint,committed_at
                FROM effects WHERE trial_id=? ORDER BY sequence
                """,
                (trial_id,),
            ).fetchall()
        return tuple(tuple(row) for row in rows)


@dataclass(frozen=True)
class ProviderAcceptResult:
    attempt_id: str
    accepted: bool
    deduplicated: bool


class SimulatedProvider:
    """Local P1-P4 provider state. Ground truth leaves only through a write-only sink."""

    _SCHEMA = """
    CREATE TABLE IF NOT EXISTS operations(
        attempt_id TEXT PRIMARY KEY,
        trial_id TEXT NOT NULL,
        stratum TEXT NOT NULL,
        effect_key TEXT NOT NULL,
        idempotency_key TEXT,
        state TEXT NOT NULL,
        delayed INTEGER NOT NULL DEFAULT 0,
        fenced INTEGER NOT NULL DEFAULT 0,
        effect_committed INTEGER NOT NULL DEFAULT 0,
        accepted_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_provider_idem ON operations(stratum,idempotency_key);
    """

    def __init__(self, state_path: Path, oracle_sink: OracleAppendSink) -> None:
        self.state_path = state_path
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        with _sqlite_connection(state_path) as connection:
            connection.executescript(self._SCHEMA)
        self._oracle_sink = oracle_sink

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.state_path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    def accept(
        self,
        *,
        trial_id: str,
        provider: ProviderStratum,
        attempt_id: str,
        effect_key: str,
        idempotency_key: str | None,
        delayed: bool = False,
    ) -> ProviderAcceptResult:
        if provider == ProviderStratum.P1 and not idempotency_key:
            raise ValueError("P1 requires a stable idempotency key")
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            existing = connection.execute(
                "SELECT attempt_id FROM operations WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            if existing is not None:
                connection.execute("COMMIT")
                return ProviderAcceptResult(attempt_id, accepted=True, deduplicated=False)
            deduplicated = False
            state = "accepted"
            committed = 0
            if provider == ProviderStratum.P1:
                prior = connection.execute(
                    """
                    SELECT effect_committed FROM operations
                    WHERE stratum=? AND idempotency_key=? AND effect_key=?
                    ORDER BY accepted_at LIMIT 1
                    """,
                    (provider.value, idempotency_key, effect_key),
                ).fetchone()
                if prior is not None and int(prior[0]) == 1:
                    deduplicated = True
                    state = "succeeded_deduplicated"
                    committed = 1
            connection.execute(
                """
                INSERT INTO operations(
                    attempt_id,trial_id,stratum,effect_key,idempotency_key,state,delayed,
                    fenced,effect_committed,accepted_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    attempt_id,
                    trial_id,
                    provider.value,
                    effect_key,
                    idempotency_key,
                    state,
                    int(delayed),
                    0,
                    committed,
                    now,
                    now,
                ),
            )
            connection.execute("COMMIT")
        return ProviderAcceptResult(attempt_id, accepted=True, deduplicated=deduplicated)

    def commit(self, attempt_id: str) -> bool:
        """Commit one business mutation; True means a newly created external effect."""

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM operations WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise KeyError(attempt_id)
            if int(row["fenced"]) == 1:
                connection.execute("COMMIT")
                return False
            if int(row["effect_committed"]) == 1:
                connection.execute("COMMIT")
                return False
            provider = ProviderStratum(str(row["stratum"]))
            if provider == ProviderStratum.P1:
                prior = connection.execute(
                    """
                    SELECT attempt_id FROM operations
                    WHERE stratum=? AND idempotency_key=? AND effect_key=?
                      AND effect_committed=1 AND attempt_id<>?
                    LIMIT 1
                    """,
                    (provider.value, row["idempotency_key"], row["effect_key"], attempt_id),
                ).fetchone()
                if prior is not None:
                    connection.execute(
                        """
                        UPDATE operations SET state='succeeded_deduplicated',effect_committed=1,
                                              updated_at=? WHERE attempt_id=?
                        """,
                        (self._now(), attempt_id),
                    )
                    connection.execute("COMMIT")
                    return False
            connection.execute(
                """
                UPDATE operations SET state='succeeded',effect_committed=1,delayed=0,updated_at=?
                WHERE attempt_id=?
                """,
                (self._now(), attempt_id),
            )
            trial_id = str(row["trial_id"])
            effect_key = str(row["effect_key"])
            idempotency_key = (
                str(row["idempotency_key"]) if row["idempotency_key"] is not None else None
            )
            connection.execute("COMMIT")
        self._oracle_sink.append(
            trial_id=trial_id,
            provider=provider,
            attempt_id=attempt_id,
            effect_key=effect_key,
            idempotency_key=idempotency_key,
        )
        return True

    def fail_without_effect(self, attempt_id: str) -> ProviderEvidence:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT stratum,effect_committed FROM operations WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise KeyError(attempt_id)
            provider = ProviderStratum(str(row["stratum"]))
            if int(row["effect_committed"]) == 1:
                connection.execute("ROLLBACK")
                raise RuntimeError("provider.effect_already_committed")
            if provider not in {ProviderStratum.P1, ProviderStratum.P2}:
                connection.execute("ROLLBACK")
                raise RuntimeError("provider.no_effect_failure_unsupported")
            connection.execute(
                "UPDATE operations SET state='failed_no_effect',delayed=0,updated_at=? WHERE attempt_id=?",
                (self._now(), attempt_id),
            )
            connection.execute("COMMIT")
        return ProviderEvidence(
            attempt_id=attempt_id,
            status="confirmed_failed",
            authoritative=True,
            no_effect_certified=True,
            predecessor_fenced=True,
        )

    def certify_no_effect_and_fence(self, attempt_id: str) -> ProviderEvidence:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT stratum,effect_committed FROM operations WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise KeyError(attempt_id)
            if ProviderStratum(str(row["stratum"])) != ProviderStratum.P3:
                connection.execute("ROLLBACK")
                raise RuntimeError("provider.fence_only_supported_in_p3")
            if int(row["effect_committed"]) == 1:
                connection.execute("ROLLBACK")
                raise RuntimeError("provider.effect_already_committed")
            connection.execute(
                """
                UPDATE operations
                SET state='certified_no_effect',fenced=1,delayed=0,updated_at=?
                WHERE attempt_id=?
                """,
                (self._now(), attempt_id),
            )
            connection.execute("COMMIT")
        return ProviderEvidence(
            attempt_id=attempt_id,
            status="confirmed_failed",
            authoritative=True,
            no_effect_certified=True,
            predecessor_fenced=True,
        )

    def status(self, attempt_id: str) -> ProviderEvidence:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT stratum,state,effect_committed,fenced FROM operations WHERE attempt_id=?",
                (attempt_id,),
            ).fetchone()
        if row is None:
            raise KeyError(attempt_id)
        provider = ProviderStratum(str(row["stratum"]))
        state = str(row["state"])
        committed = int(row["effect_committed"]) == 1
        fenced = int(row["fenced"]) == 1
        if provider == ProviderStratum.P4:
            return ProviderEvidence(attempt_id, "still_unknown", authoritative=False)
        if committed:
            return ProviderEvidence(attempt_id, "confirmed_succeeded", authoritative=True)
        if state in {"failed_no_effect", "certified_no_effect"}:
            return ProviderEvidence(
                attempt_id,
                "confirmed_failed",
                authoritative=True,
                no_effect_certified=True,
                predecessor_fenced=(fenced or provider in {ProviderStratum.P1, ProviderStratum.P2}),
            )
        return ProviderEvidence(attempt_id, "still_unknown", authoritative=True)

    def set_delayed(self, attempt_id: str) -> None:
        with self._connect() as connection:
            updated = connection.execute(
                "UPDATE operations SET delayed=1,state='pending',updated_at=? WHERE attempt_id=?",
                (self._now(), attempt_id),
            )
            if updated.rowcount != 1:
                raise KeyError(attempt_id)

    def release_delayed(self, attempt_id: str) -> bool:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT delayed,fenced FROM operations WHERE attempt_id=?", (attempt_id,)
            ).fetchone()
        if row is None:
            raise KeyError(attempt_id)
        if int(row["delayed"]) != 1 or int(row["fenced"]) == 1:
            return False
        return self.commit(attempt_id)

    def sends(self, trial_id: str) -> int:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT COUNT(*) FROM operations WHERE trial_id=?", (trial_id,)
            ).fetchone()
        return int(row[0]) if row is not None else 0
