from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Iterator

from agentguard.domain import (
    EvidenceTrustLevel,
    ExecutionResolution,
    ExecutionState,
    ReconciliationEvidence,
    ReconciliationStatus,
)
from agentguard.engine.canonical import digest
from agentguard.ports.reconciliation_work import ReconciliationLease

from .state import SQLiteState

TERMINAL_RECONCILIATION_STATUSES = frozenset(
    {
        ReconciliationStatus.CONFIRMED_SUCCEEDED,
        ReconciliationStatus.CONFIRMED_FAILED,
        ReconciliationStatus.CONFLICT,
    }
)


class ReconciliationLeaseError(RuntimeError):
    pass


class SQLiteFencedReconciliationState(SQLiteState):
    """SQLite state with process-safe reconciliation leases and atomic resolution fencing."""

    _LEASE_SCHEMA = """
    CREATE TABLE IF NOT EXISTS reconciliation_work_fence(
        singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
        next_token INTEGER NOT NULL
    );
    INSERT OR IGNORE INTO reconciliation_work_fence(singleton, next_token) VALUES(1, 1);
    CREATE TABLE IF NOT EXISTS reconciliation_work_leases(
        execution_id TEXT PRIMARY KEY,
        owner_id TEXT NOT NULL,
        fencing_token INTEGER NOT NULL,
        acquired_at TEXT NOT NULL,
        expires_at TEXT NOT NULL,
        FOREIGN KEY(execution_id) REFERENCES executions(execution_id)
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_reconciliation_work_fencing_token
    ON reconciliation_work_leases(fencing_token);
    """

    def __init__(self, path: Path) -> None:
        super().__init__(path)
        self._active_resolution_lease: ContextVar[ReconciliationLease | None] = ContextVar(
            f"agentguard_resolution_lease_{id(self)}", default=None
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                for raw_statement in self._LEASE_SCHEMA.split(";"):
                    statement = raw_statement.strip()
                    if statement:
                        connection.execute(statement)
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise

    @staticmethod
    def _require_aware(value: datetime, code: str) -> None:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ReconciliationLeaseError(code)

    @staticmethod
    def _validate_lease_request(owner_id: str, now: datetime, lease_seconds: int) -> None:
        SQLiteFencedReconciliationState._require_aware(now, "reconciliation.lease_now_invalid")
        if not owner_id.strip():
            raise ReconciliationLeaseError("reconciliation.lease_owner_invalid")
        if lease_seconds < 1:
            raise ReconciliationLeaseError("reconciliation.lease_ttl_invalid")

    @staticmethod
    def _lease_from_row(row: sqlite3.Row) -> ReconciliationLease:
        return ReconciliationLease(
            execution_id=str(row["execution_id"]),
            owner_id=str(row["owner_id"]),
            fencing_token=int(row["fencing_token"]),
            acquired_at=datetime.fromisoformat(str(row["acquired_at"])).astimezone(UTC),
            expires_at=datetime.fromisoformat(str(row["expires_at"])).astimezone(UTC),
        )

    def claim_reconciliation_lease(
        self,
        execution_id: str,
        owner_id: str,
        *,
        now: datetime,
        lease_seconds: int,
        allow_terminal_recheck: bool = False,
    ) -> ReconciliationLease | None:
        self._validate_lease_request(owner_id, now, lease_seconds)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                now = self._transaction_now()
                expires_at = now + timedelta(seconds=lease_seconds)
                execution = connection.execute(
                    "SELECT state FROM executions WHERE execution_id = ?",
                    (execution_id,),
                ).fetchone()
                if execution is None:
                    raise ReconciliationLeaseError("execution.record_missing")
                if ExecutionState(str(execution[0])) != ExecutionState.UNKNOWN:
                    connection.execute("COMMIT")
                    return None

                latest_resolution = connection.execute(
                    """
                    SELECT status FROM execution_resolutions
                    WHERE execution_id = ? ORDER BY sequence DESC LIMIT 1
                    """,
                    (execution_id,),
                ).fetchone()
                if latest_resolution is not None:
                    status = ReconciliationStatus(str(latest_resolution[0]))
                    if status == ReconciliationStatus.CONFLICT:
                        connection.execute("COMMIT")
                        return None
                    if not allow_terminal_recheck and status in TERMINAL_RECONCILIATION_STATUSES:
                        connection.execute("COMMIT")
                        return None

                existing = connection.execute(
                    """
                    SELECT execution_id,owner_id,fencing_token,acquired_at,expires_at
                    FROM reconciliation_work_leases WHERE execution_id = ?
                    """,
                    (execution_id,),
                ).fetchone()
                if existing is not None:
                    current = self._lease_from_row(existing)
                    if current.expires_at > now:
                        connection.execute("COMMIT")
                        return None

                token_row = connection.execute(
                    "SELECT next_token FROM reconciliation_work_fence WHERE singleton = 1"
                ).fetchone()
                if token_row is None:
                    raise ReconciliationLeaseError("reconciliation.fence_state_missing")
                fencing_token = int(token_row[0])
                connection.execute(
                    "UPDATE reconciliation_work_fence SET next_token = ? WHERE singleton = 1",
                    (fencing_token + 1,),
                )
                connection.execute(
                    """
                    INSERT INTO reconciliation_work_leases(
                        execution_id,owner_id,fencing_token,acquired_at,expires_at
                    ) VALUES(?,?,?,?,?)
                    ON CONFLICT(execution_id) DO UPDATE SET
                        owner_id=excluded.owner_id,
                        fencing_token=excluded.fencing_token,
                        acquired_at=excluded.acquired_at,
                        expires_at=excluded.expires_at
                    """,
                    (
                        execution_id,
                        owner_id,
                        fencing_token,
                        now.isoformat(),
                        expires_at.isoformat(),
                    ),
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return ReconciliationLease(
            execution_id=execution_id,
            owner_id=owner_id,
            fencing_token=fencing_token,
            acquired_at=now,
            expires_at=expires_at,
        )

    def renew_reconciliation_lease(
        self,
        lease: ReconciliationLease,
        *,
        now: datetime,
        lease_seconds: int,
    ) -> ReconciliationLease:
        self._validate_lease_request(lease.owner_id, now, lease_seconds)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                now = self._transaction_now()
                expires_at = now + timedelta(seconds=lease_seconds)
                row = connection.execute(
                    """
                    SELECT owner_id,fencing_token,expires_at
                    FROM reconciliation_work_leases WHERE execution_id = ?
                    """,
                    (lease.execution_id,),
                ).fetchone()
                if (
                    row is None
                    or str(row["owner_id"]) != lease.owner_id
                    or int(row["fencing_token"]) != lease.fencing_token
                    or datetime.fromisoformat(str(row["expires_at"])).astimezone(UTC) <= now
                ):
                    raise ReconciliationLeaseError("reconciliation.lease_lost")
                updated = connection.execute(
                    """
                    UPDATE reconciliation_work_leases SET expires_at = ?
                    WHERE execution_id = ? AND owner_id = ? AND fencing_token = ?
                    """,
                    (
                        expires_at.isoformat(),
                        lease.execution_id,
                        lease.owner_id,
                        lease.fencing_token,
                    ),
                )
                if updated.rowcount != 1:
                    raise ReconciliationLeaseError("reconciliation.lease_lost")
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return ReconciliationLease(
            execution_id=lease.execution_id,
            owner_id=lease.owner_id,
            fencing_token=lease.fencing_token,
            acquired_at=lease.acquired_at.astimezone(UTC),
            expires_at=expires_at,
        )

    def release_reconciliation_lease(self, lease: ReconciliationLease) -> bool:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                deleted = connection.execute(
                    """
                    DELETE FROM reconciliation_work_leases
                    WHERE execution_id = ? AND owner_id = ? AND fencing_token = ?
                    """,
                    (lease.execution_id, lease.owner_id, lease.fencing_token),
                )
                connection.execute("COMMIT")
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
        return deleted.rowcount == 1

    def get_reconciliation_lease(self, execution_id: str) -> ReconciliationLease | None:
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT execution_id,owner_id,fencing_token,acquired_at,expires_at
                FROM reconciliation_work_leases WHERE execution_id = ?
                """,
                (execution_id,),
            ).fetchone()
        return self._lease_from_row(row) if row is not None else None

    @contextmanager
    def resolution_lease(self, lease: ReconciliationLease) -> Iterator[None]:
        active = self._active_resolution_lease.get()
        if active is not None:
            raise ReconciliationLeaseError("reconciliation.lease_scope_nested")
        token = self._active_resolution_lease.set(lease)
        try:
            yield
        finally:
            self._active_resolution_lease.reset(token)

    @staticmethod
    def _delete_exact_lease(connection: sqlite3.Connection, lease: ReconciliationLease) -> None:
        connection.execute(
            """
            DELETE FROM reconciliation_work_leases
            WHERE execution_id = ? AND owner_id = ? AND fencing_token = ?
            """,
            (lease.execution_id, lease.owner_id, lease.fencing_token),
        )

    def record_execution_resolution(
        self,
        execution_id: str,
        evidence: ReconciliationEvidence,
        reconciled_at: datetime,
    ) -> ExecutionResolution:
        lease = self._active_resolution_lease.get()
        if lease is None:
            raise ReconciliationLeaseError("reconciliation.lease_required")
        if lease.execution_id != execution_id:
            raise ReconciliationLeaseError("reconciliation.lease_execution_mismatch")
        self._require_aware(reconciled_at, "reconciliation.reconciled_at_invalid")
        reconciled_at = reconciled_at.astimezone(UTC)

        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            try:
                admission_at = self._transaction_now()
                lease_row = connection.execute(
                    """
                    SELECT owner_id,fencing_token,expires_at
                    FROM reconciliation_work_leases WHERE execution_id = ?
                    """,
                    (execution_id,),
                ).fetchone()
                if (
                    lease_row is None
                    or str(lease_row["owner_id"]) != lease.owner_id
                    or int(lease_row["fencing_token"]) != lease.fencing_token
                    or datetime.fromisoformat(str(lease_row["expires_at"])).astimezone(UTC)
                    <= admission_at
                ):
                    raise ReconciliationLeaseError("reconciliation.lease_lost")

                execution_row = connection.execute(
                    "SELECT state FROM executions WHERE execution_id = ?",
                    (execution_id,),
                ).fetchone()
                if execution_row is None:
                    raise RuntimeError("execution.record_missing")
                execution_state = ExecutionState(str(execution_row[0]))
                if execution_state != ExecutionState.UNKNOWN:
                    raise RuntimeError("reconciliation.execution_not_unknown")

                existing_row = connection.execute(
                    """
                    SELECT resolution_id,execution_id,original_state,status,source,evidence_digest,
                           trust_level,provider_operation_id_digest,observed_at,reconciled_at,error_code
                    FROM execution_resolutions
                    WHERE execution_id = ? ORDER BY sequence DESC LIMIT 1
                    """,
                    (execution_id,),
                ).fetchone()
                existing = self._resolution(existing_row) if existing_row is not None else None

                if existing is not None and existing.status == ReconciliationStatus.CONFLICT:
                    self._delete_exact_lease(connection, lease)
                    connection.execute("COMMIT")
                    return existing
                if (
                    existing is not None
                    and existing.status == evidence.status
                    and existing.evidence_digest == evidence.evidence_digest
                    and existing.trust_level == evidence.trust_level
                ):
                    self._delete_exact_lease(connection, lease)
                    connection.execute("COMMIT")
                    return existing
                if (
                    existing is not None
                    and existing.status
                    in {
                        ReconciliationStatus.CONFIRMED_SUCCEEDED,
                        ReconciliationStatus.CONFIRMED_FAILED,
                    }
                    and evidence.status
                    in {ReconciliationStatus.STILL_UNKNOWN, ReconciliationStatus.UNSUPPORTED}
                ):
                    self._delete_exact_lease(connection, lease)
                    connection.execute("COMMIT")
                    return existing

                selected_status = evidence.status
                selected_source = evidence.source
                selected_digest = evidence.evidence_digest
                selected_trust = evidence.trust_level
                selected_error = evidence.error_code
                if (
                    existing is not None
                    and existing.status
                    in {
                        ReconciliationStatus.CONFIRMED_SUCCEEDED,
                        ReconciliationStatus.CONFIRMED_FAILED,
                    }
                    and evidence.status
                    in {
                        ReconciliationStatus.CONFIRMED_SUCCEEDED,
                        ReconciliationStatus.CONFIRMED_FAILED,
                    }
                    and existing.status != evidence.status
                ):
                    selected_status = ReconciliationStatus.CONFLICT
                    selected_source = "agentguard"
                    selected_digest = digest(
                        {
                            "previous_resolution": existing.resolution_id,
                            "previous_evidence": existing.evidence_digest,
                            "new_evidence": evidence.evidence_digest,
                        }
                    )
                    selected_trust = EvidenceTrustLevel.AGENTGUARD_SIGNED
                    selected_error = "reconciliation.conflicting_evidence"

                provider_operation_id_digest = (
                    digest(evidence.provider_operation_id)
                    if evidence.provider_operation_id is not None
                    else None
                )
                resolution = ExecutionResolution(
                    resolution_id="res_" + __import__("uuid").uuid4().hex,
                    execution_id=execution_id,
                    original_state=execution_state,
                    status=selected_status,
                    source=selected_source,
                    evidence_digest=selected_digest,
                    trust_level=selected_trust,
                    provider_operation_id_digest=provider_operation_id_digest,
                    observed_at=evidence.observed_at,
                    reconciled_at=reconciled_at,
                    error_code=selected_error,
                )
                connection.execute(
                    """
                    INSERT INTO execution_resolutions(
                        resolution_id,execution_id,original_state,status,source,evidence_digest,
                        trust_level,provider_operation_id_digest,observed_at,reconciled_at,error_code
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        resolution.resolution_id,
                        resolution.execution_id,
                        resolution.original_state.value,
                        resolution.status.value,
                        resolution.source,
                        resolution.evidence_digest,
                        resolution.trust_level.value,
                        resolution.provider_operation_id_digest,
                        resolution.observed_at.isoformat(),
                        resolution.reconciled_at.isoformat(),
                        resolution.error_code,
                    ),
                )
                self._delete_exact_lease(connection, lease)
                connection.execute("COMMIT")
                return resolution
            except Exception:
                if connection.in_transaction:
                    connection.execute("ROLLBACK")
                raise
