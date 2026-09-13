from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .models import AttemptState, ProviderEvidence, ProviderStratum, SlotState


class LineageLedgerError(RuntimeError):
    pass


@dataclass(frozen=True)
class SlotSnapshot:
    alpha: str
    effect_key: str
    slot_id: str
    state: SlotState
    root_handle: str | None
    attempt_count: int


class AuthorizationInstanceLedger:
    """Research-only durable ledger for one token-independent authorization instance.

    The ledger deliberately uses ordinary SQLite transactions. A1 composes this with the real
    AgentGuard protected path; B4 uses it as the conventional durable baseline. It is not a new
    production persistence adapter.
    """

    _SCHEMA = """
    PRAGMA foreign_keys = ON;
    CREATE TABLE IF NOT EXISTS authorization_instances(
        alpha TEXT PRIMARY KEY,
        effect_key TEXT NOT NULL,
        budget INTEGER NOT NULL CHECK(budget = 1),
        slot_id TEXT NOT NULL UNIQUE,
        slot_state TEXT NOT NULL,
        root_claim_token TEXT,
        root_handle TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS attempts(
        attempt_id TEXT PRIMARY KEY,
        alpha TEXT NOT NULL,
        slot_id TEXT NOT NULL,
        parent_attempt_id TEXT,
        state TEXT NOT NULL,
        provider_stratum TEXT NOT NULL,
        idempotency_key TEXT,
        potentially_effectful INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY(alpha) REFERENCES authorization_instances(alpha)
    );
    CREATE INDEX IF NOT EXISTS idx_attempts_alpha ON attempts(alpha, created_at);
    CREATE TABLE IF NOT EXISTS lineage_events(
        sequence INTEGER PRIMARY KEY AUTOINCREMENT,
        alpha TEXT NOT NULL,
        event_type TEXT NOT NULL,
        detail TEXT,
        recorded_at TEXT NOT NULL
    );
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(self._SCHEMA)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=30.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    @staticmethod
    def _now() -> str:
        return datetime.now(UTC).isoformat()

    @staticmethod
    def _event(
        connection: sqlite3.Connection, alpha: str, event_type: str, detail: str | None = None
    ) -> None:
        connection.execute(
            "INSERT INTO lineage_events(alpha,event_type,detail,recorded_at) VALUES(?,?,?,?)",
            (alpha, event_type, detail, AuthorizationInstanceLedger._now()),
        )

    def register(self, alpha: str, effect_key: str) -> SlotSnapshot:
        if not alpha or not effect_key:
            raise ValueError("alpha and effect_key are required")
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT * FROM authorization_instances WHERE alpha = ?", (alpha,)
            ).fetchone()
            if row is None:
                slot_id = "slot_" + uuid4().hex
                connection.execute(
                    """
                    INSERT INTO authorization_instances(
                        alpha,effect_key,budget,slot_id,slot_state,created_at,updated_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (alpha, effect_key, 1, slot_id, SlotState.AVAILABLE.value, now, now),
                )
                self._event(connection, alpha, "authorization.registered", slot_id)
            elif str(row["effect_key"]) != effect_key or int(row["budget"]) != 1:
                connection.execute("ROLLBACK")
                raise LineageLedgerError("lineage.authorization_instance_mismatch")
            else:
                self._event(connection, alpha, "authorization.replayed", str(row["slot_id"]))
            connection.execute("COMMIT")
        return self.snapshot(alpha)

    def claim_root(self, alpha: str, claim_token: str) -> bool:
        """Claim the sole AgentGuard root-issuance opportunity for A1.

        A crash after this claim is conservative: the claim remains occupied and cannot silently mint
        another root. Recovery is intentionally not automatic in the research implementation.
        """

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT root_claim_token,root_handle FROM authorization_instances WHERE alpha = ?",
                (alpha,),
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise LineageLedgerError("lineage.authorization_instance_missing")
            existing_claim = row["root_claim_token"]
            existing_handle = row["root_handle"]
            if existing_handle is not None:
                connection.execute("COMMIT")
                return False
            if existing_claim is None:
                connection.execute(
                    "UPDATE authorization_instances SET root_claim_token=?,updated_at=? WHERE alpha=?",
                    (claim_token, self._now(), alpha),
                )
                self._event(connection, alpha, "root.claimed", claim_token)
                connection.execute("COMMIT")
                return True
            connection.execute("COMMIT")
            return str(existing_claim) == claim_token

    def bind_root(self, alpha: str, claim_token: str, root_handle: str) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                """
                UPDATE authorization_instances
                SET root_handle=?,updated_at=?
                WHERE alpha=? AND root_claim_token=? AND root_handle IS NULL
                """,
                (root_handle, self._now(), alpha, claim_token),
            )
            if updated.rowcount != 1:
                connection.execute("ROLLBACK")
                raise LineageLedgerError("lineage.root_claim_lost")
            self._event(connection, alpha, "root.bound", root_handle)
            connection.execute("COMMIT")

    def root_handle(self, alpha: str) -> str | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT root_handle FROM authorization_instances WHERE alpha=?", (alpha,)
            ).fetchone()
        if row is None:
            raise LineageLedgerError("lineage.authorization_instance_missing")
        return str(row[0]) if row[0] is not None else None

    def reserve_slot(self, alpha: str) -> SlotSnapshot:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT slot_state,slot_id FROM authorization_instances WHERE alpha=?", (alpha,)
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise LineageLedgerError("lineage.authorization_instance_missing")
            state = SlotState(str(row["slot_state"]))
            if state == SlotState.AVAILABLE:
                connection.execute(
                    "UPDATE authorization_instances SET slot_state=?,updated_at=? WHERE alpha=?",
                    (SlotState.RESERVED.value, self._now(), alpha),
                )
                self._event(connection, alpha, "slot.reserved", str(row["slot_id"]))
            elif state not in {SlotState.RESERVED, SlotState.DISPATCHING, SlotState.UNKNOWN}:
                connection.execute("ROLLBACK")
                raise LineageLedgerError("lineage.slot_not_reservable")
            connection.execute("COMMIT")
        return self.snapshot(alpha)

    def begin_attempt(
        self,
        alpha: str,
        provider: ProviderStratum,
        *,
        parent_attempt_id: str | None = None,
        idempotency_key: str | None = None,
        allow_same_slot_retry: bool = False,
    ) -> str:
        attempt_id = "attempt_" + uuid4().hex
        now = self._now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT slot_id,slot_state FROM authorization_instances WHERE alpha=?", (alpha,)
            ).fetchone()
            if row is None:
                connection.execute("ROLLBACK")
                raise LineageLedgerError("lineage.authorization_instance_missing")
            state = SlotState(str(row["slot_state"]))
            allowed = state == SlotState.RESERVED
            if allow_same_slot_retry and provider == ProviderStratum.P1 and state == SlotState.UNKNOWN:
                allowed = True
                if idempotency_key is None:
                    connection.execute("ROLLBACK")
                    raise LineageLedgerError("lineage.p1_retry_requires_idempotency_key")
                previous = connection.execute(
                    """
                    SELECT idempotency_key FROM attempts
                    WHERE alpha=? ORDER BY created_at DESC LIMIT 1
                    """,
                    (alpha,),
                ).fetchone()
                if previous is None or previous[0] != idempotency_key:
                    connection.execute("ROLLBACK")
                    raise LineageLedgerError("lineage.p1_retry_key_changed")
            if not allowed:
                connection.execute("ROLLBACK")
                raise LineageLedgerError("lineage.successor_not_admissible")
            if parent_attempt_id is not None:
                parent = connection.execute(
                    "SELECT alpha FROM attempts WHERE attempt_id=?", (parent_attempt_id,)
                ).fetchone()
                if parent is None or str(parent[0]) != alpha:
                    connection.execute("ROLLBACK")
                    raise LineageLedgerError("lineage.parent_attempt_invalid")
            connection.execute(
                """
                INSERT INTO attempts(
                    attempt_id,alpha,slot_id,parent_attempt_id,state,provider_stratum,
                    idempotency_key,created_at,updated_at
                ) VALUES(?,?,?,?,?,?,?,?,?)
                """,
                (
                    attempt_id,
                    alpha,
                    str(row["slot_id"]),
                    parent_attempt_id,
                    AttemptState.RESERVED.value,
                    provider.value,
                    idempotency_key,
                    now,
                    now,
                ),
            )
            self._event(connection, alpha, "attempt.created", attempt_id)
            connection.execute("COMMIT")
        return attempt_id

    def mark_dispatching(self, alpha: str, attempt_id: str) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                """
                UPDATE attempts SET state=?,potentially_effectful=1,updated_at=?
                WHERE attempt_id=? AND alpha=? AND state=?
                """,
                (
                    AttemptState.DISPATCHING.value,
                    self._now(),
                    attempt_id,
                    alpha,
                    AttemptState.RESERVED.value,
                ),
            )
            if updated.rowcount != 1:
                connection.execute("ROLLBACK")
                raise LineageLedgerError("lineage.attempt_not_reserved")
            connection.execute(
                "UPDATE authorization_instances SET slot_state=?,updated_at=? WHERE alpha=?",
                (SlotState.DISPATCHING.value, self._now(), alpha),
            )
            self._event(connection, alpha, "attempt.dispatching", attempt_id)
            connection.execute("COMMIT")

    def mark_unknown(self, alpha: str, attempt_id: str) -> None:
        self._set_attempt_and_slot(
            alpha,
            attempt_id,
            AttemptState.UNKNOWN,
            SlotState.UNKNOWN,
            "attempt.unknown",
        )

    def mark_effect(self, alpha: str, attempt_id: str) -> None:
        self._set_attempt_and_slot(
            alpha,
            attempt_id,
            AttemptState.CONFIRMED_EFFECT,
            SlotState.CONFIRMED_EFFECT,
            "attempt.confirmed_effect",
        )

    def apply_no_effect_evidence(
        self,
        alpha: str,
        evidence: ProviderEvidence,
        provider: ProviderStratum,
    ) -> None:
        if not evidence.authoritative or not evidence.no_effect_certified:
            raise LineageLedgerError("lineage.no_effect_not_proven")
        if provider == ProviderStratum.P3 and not evidence.predecessor_fenced:
            raise LineageLedgerError("lineage.p3_fence_required")
        if provider == ProviderStratum.P4:
            raise LineageLedgerError("lineage.p4_cannot_release_unknown")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                """
                UPDATE attempts SET state=?,potentially_effectful=0,updated_at=?
                WHERE attempt_id=? AND alpha=?
                  AND state IN (?,?)
                """,
                (
                    AttemptState.CONFIRMED_NO_EFFECT.value,
                    self._now(),
                    evidence.attempt_id,
                    alpha,
                    AttemptState.DISPATCHING.value,
                    AttemptState.UNKNOWN.value,
                ),
            )
            if updated.rowcount != 1:
                connection.execute("ROLLBACK")
                raise LineageLedgerError("lineage.attempt_not_releasable")
            connection.execute(
                "UPDATE authorization_instances SET slot_state=?,updated_at=? WHERE alpha=?",
                (SlotState.RESERVED.value, self._now(), alpha),
            )
            self._event(connection, alpha, "slot.transferred_after_no_effect", evidence.attempt_id)
            connection.execute("COMMIT")

    def _set_attempt_and_slot(
        self,
        alpha: str,
        attempt_id: str,
        attempt_state: AttemptState,
        slot_state: SlotState,
        event_type: str,
    ) -> None:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            updated = connection.execute(
                "UPDATE attempts SET state=?,updated_at=? WHERE attempt_id=? AND alpha=?",
                (attempt_state.value, self._now(), attempt_id, alpha),
            )
            if updated.rowcount != 1:
                connection.execute("ROLLBACK")
                raise LineageLedgerError("lineage.attempt_missing")
            connection.execute(
                "UPDATE authorization_instances SET slot_state=?,updated_at=? WHERE alpha=?",
                (slot_state.value, self._now(), alpha),
            )
            self._event(connection, alpha, event_type, attempt_id)
            connection.execute("COMMIT")

    def snapshot(self, alpha: str) -> SlotSnapshot:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM authorization_instances WHERE alpha=?", (alpha,)
            ).fetchone()
            attempts = connection.execute(
                "SELECT COUNT(*) FROM attempts WHERE alpha=?", (alpha,)
            ).fetchone()
        if row is None or attempts is None:
            raise LineageLedgerError("lineage.authorization_instance_missing")
        return SlotSnapshot(
            alpha=alpha,
            effect_key=str(row["effect_key"]),
            slot_id=str(row["slot_id"]),
            state=SlotState(str(row["slot_state"])),
            root_handle=str(row["root_handle"]) if row["root_handle"] is not None else None,
            attempt_count=int(attempts[0]),
        )

    def counts(self, alpha: str) -> dict[str, int]:
        with self._connect() as connection:
            root = connection.execute(
                "SELECT root_handle FROM authorization_instances WHERE alpha=?", (alpha,)
            ).fetchone()
            attempts = connection.execute(
                "SELECT COUNT(*) FROM attempts WHERE alpha=?", (alpha,)
            ).fetchone()
            sends = connection.execute(
                "SELECT COUNT(*) FROM attempts WHERE alpha=? AND potentially_effectful=1",
                (alpha,),
            ).fetchone()
        if root is None or attempts is None or sends is None:
            raise LineageLedgerError("lineage.authorization_instance_missing")
        return {
            "root_or_slot_allocations": 1,
            "root_handle_bound": int(root[0] is not None),
            "attempts": int(attempts[0]),
            "potentially_effectful_attempts": int(sends[0]),
        }
