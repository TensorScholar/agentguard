from __future__ import annotations

import sqlite3
from datetime import datetime
from hashlib import sha256
from pathlib import Path

from agentguard.domain import (
    ApprovalReceipt,
    AttestationMetadata,
    AuditEvent,
    AuthorityGrant,
    AuthorityGrantRecord,
    AuthorityGrantStatus,
    CapabilityLease,
    CapabilityLeaseStatus,
    EvidenceTrustLevel,
    ExecutionRecord,
    ExecutionResolution,
    ExecutionState,
    ReconciliationEvidence,
    ReconciliationStatus,
    VerifiedExecution,
)
from agentguard.engine.canonical import canonical_bytes, digest
from agentguard.engine.execution import execution_authority_digest
from agentguard.security.files import ensure_private_file

GENESIS = "0" * 64
SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS consumed_nonces(
 nonce TEXT PRIMARY KEY, decision_id TEXT NOT NULL, consumed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS audit_events(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 event_id TEXT UNIQUE NOT NULL, event_json TEXT NOT NULL,
 previous_hash TEXT NOT NULL, event_hash TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS approvals(
 approval_id TEXT PRIMARY KEY, decision_id TEXT NOT NULL, receipt_json TEXT NOT NULL,
 used_count INTEGER NOT NULL DEFAULT 0, maximum_uses INTEGER NOT NULL, expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS credential_issuance_claims(
 request_id TEXT PRIMARY KEY,
 decision_id TEXT NOT NULL,
 approval_id TEXT,
 single_use INTEGER NOT NULL,
 status TEXT NOT NULL,
 issuance_id TEXT,
 claimed_at TEXT NOT NULL,
 completed_at TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS idx_single_use_credential_decision
ON credential_issuance_claims(decision_id) WHERE single_use = 1;
CREATE TABLE IF NOT EXISTS executions(
 execution_id TEXT PRIMARY KEY,
 decision_id TEXT UNIQUE NOT NULL,
 nonce TEXT UNIQUE NOT NULL,
 trace_id TEXT NOT NULL,
 request_id TEXT NOT NULL,
 intent_digest TEXT NOT NULL,
 authority_digest TEXT NOT NULL,
 policy_digest TEXT,
 authority_grant_id TEXT,
 authority_lease_id TEXT,
 authority_chain_digest TEXT,
 state TEXT NOT NULL,
 reserved_at TEXT NOT NULL,
 dispatching_at TEXT,
 completed_at TEXT,
 provider_status INTEGER,
 result_digest TEXT,
 error_code TEXT
);
CREATE TABLE IF NOT EXISTS agentguard_schema(
 component TEXT PRIMARY KEY, version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS execution_resolutions(
 sequence INTEGER PRIMARY KEY AUTOINCREMENT,
 resolution_id TEXT UNIQUE NOT NULL,
 execution_id TEXT NOT NULL,
 original_state TEXT NOT NULL,
 status TEXT NOT NULL,
 source TEXT NOT NULL,
 evidence_digest TEXT NOT NULL,
 trust_level TEXT NOT NULL,
 provider_operation_id_digest TEXT,
 observed_at TEXT NOT NULL,
 reconciled_at TEXT NOT NULL,
 error_code TEXT,
 FOREIGN KEY(execution_id) REFERENCES executions(execution_id)
);
CREATE TABLE IF NOT EXISTS execution_attestations(
 attestation_id TEXT PRIMARY KEY,
 execution_id TEXT NOT NULL,
 payload_digest TEXT NOT NULL,
 signature_digest TEXT NOT NULL,
 signer_key_id TEXT NOT NULL,
 previous_attestation_digest TEXT,
 issued_at TEXT NOT NULL,
 FOREIGN KEY(execution_id) REFERENCES executions(execution_id)
);
CREATE TABLE IF NOT EXISTS authority_grants(
 grant_id TEXT PRIMARY KEY,
 parent_grant_id TEXT,
 grant_json TEXT NOT NULL,
 status TEXT NOT NULL,
 remaining_calls INTEGER NOT NULL,
 revoked_at TEXT,
 revoke_reason TEXT,
 expires_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS capability_leases(
 lease_id TEXT PRIMARY KEY,
 grant_id TEXT NOT NULL,
 maximum_uses INTEGER NOT NULL,
 remaining_uses INTEGER NOT NULL,
 issued_at TEXT NOT NULL,
 expires_at TEXT NOT NULL,
 status TEXT NOT NULL,
 FOREIGN KEY(grant_id) REFERENCES authority_grants(grant_id)
);
INSERT OR IGNORE INTO agentguard_schema(component, version) VALUES('action_integrity', 6);
UPDATE agentguard_schema SET version = 6 WHERE component = 'action_integrity';
"""

V2_AUDIT_COLUMNS = {
    "sequence",
    "event_id",
    "event_json",
    "previous_hash",
    "event_hash",
}

_TERMINAL_STATES = {ExecutionState.SUCCEEDED, ExecutionState.FAILED, ExecutionState.UNKNOWN}


class IncompatibleStateDatabaseError(RuntimeError):
    """Raised rather than silently mixing v0.1 and v0.2 SQLite schemas."""


class SQLiteState:
    def __init__(self, path: Path) -> None:
        self.path = path
        ensure_private_file(path)
        with self._connect() as c:
            existing_columns = {
                str(row[1]) for row in c.execute("PRAGMA table_info(audit_events)").fetchall()
            }
            if existing_columns and existing_columns != V2_AUDIT_COLUMNS:
                raise IncompatibleStateDatabaseError(
                    "existing SQLite audit state is not the v0.2 schema; "
                    "retain it as v0.1 evidence and choose a new database path"
                )
            c.executescript(SCHEMA)
            execution_columns = {
                str(row[1]) for row in c.execute("PRAGMA table_info(executions)").fetchall()
            }
            for column in (
                "policy_digest",
                "authority_grant_id",
                "authority_lease_id",
                "authority_chain_digest",
            ):
                if column not in execution_columns:
                    c.execute(f"ALTER TABLE executions ADD COLUMN {column} TEXT")

    def _connect(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        c.execute("PRAGMA busy_timeout=10000")
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA trusted_schema=OFF")
        c.execute("PRAGMA synchronous=FULL")
        c.execute("PRAGMA secure_delete=ON")
        return c

    @staticmethod
    def _execution_record(row: sqlite3.Row | tuple[object, ...]) -> ExecutionRecord:
        provider_status = row[14]
        if provider_status is not None and not isinstance(provider_status, int):
            raise ValueError("execution provider_status must be an integer")

        return ExecutionRecord(
            execution_id=str(row[0]),
            decision_id=str(row[1]),
            trace_id=str(row[2]),
            request_id=str(row[3]),
            intent_digest=str(row[4]),
            authority_digest=str(row[5]),
            policy_digest=str(row[6]) if row[6] is not None else None,
            authority_grant_id=str(row[7]) if row[7] is not None else None,
            authority_lease_id=str(row[8]) if row[8] is not None else None,
            authority_chain_digest=str(row[9]) if row[9] is not None else None,
            state=ExecutionState(str(row[10])),
            reserved_at=datetime.fromisoformat(str(row[11])),
            dispatching_at=(datetime.fromisoformat(str(row[12])) if row[12] is not None else None),
            completed_at=(datetime.fromisoformat(str(row[13])) if row[13] is not None else None),
            provider_status=provider_status,
            result_digest=str(row[15]) if row[15] is not None else None,
            error_code=str(row[16]) if row[16] is not None else None,
        )

    def consume(self, nonce: str, decision_id: str, consumed_at: datetime) -> bool:
        """Legacy compatibility method; protected execution uses reserve_execution instead."""

        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                c.execute(
                    "INSERT INTO consumed_nonces(nonce,decision_id,consumed_at) VALUES(?,?,?)",
                    (nonce, decision_id, consumed_at.isoformat()),
                )
                c.execute("COMMIT")
                return True
            except sqlite3.IntegrityError:
                c.execute("ROLLBACK")
                return False

    def reserve_execution(
        self,
        verified_execution: VerifiedExecution,
        reserved_at: datetime,
    ) -> str | None:
        """Atomically claim the nonce/decision and create the durable RESERVED execution."""

        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                c.execute(
                    "INSERT INTO consumed_nonces(nonce,decision_id,consumed_at) VALUES(?,?,?)",
                    (
                        verified_execution.nonce,
                        verified_execution.decision_id,
                        reserved_at.isoformat(),
                    ),
                )
                if verified_execution.authority_lease_id is not None:
                    lease_update = c.execute(
                        """
                        UPDATE capability_leases
                        SET remaining_uses = remaining_uses - 1,
                            status = CASE WHEN remaining_uses - 1 = 0 THEN ? ELSE status END
                        WHERE lease_id = ?
                          AND grant_id = ?
                          AND status = ?
                          AND remaining_uses > 0
                          AND expires_at > ?
                          AND EXISTS (
                              SELECT 1 FROM authority_grants g
                              WHERE g.grant_id = capability_leases.grant_id
                                AND g.status = ?
                                AND g.expires_at > ?
                          )
                        """,
                        (
                            CapabilityLeaseStatus.EXHAUSTED.value,
                            verified_execution.authority_lease_id,
                            verified_execution.authority_grant_id,
                            CapabilityLeaseStatus.ACTIVE.value,
                            reserved_at.isoformat(),
                            AuthorityGrantStatus.ACTIVE.value,
                            reserved_at.isoformat(),
                        ),
                    )
                    if lease_update.rowcount != 1:
                        raise sqlite3.IntegrityError("authority.lease_unavailable")
                c.execute(
                    """
                    INSERT INTO executions(
                        execution_id,decision_id,nonce,trace_id,request_id,intent_digest,
                        authority_digest,policy_digest,authority_grant_id,authority_lease_id,
                        authority_chain_digest,state,reserved_at
                    ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        verified_execution.execution_id,
                        verified_execution.decision_id,
                        verified_execution.nonce,
                        verified_execution.trace_id,
                        verified_execution.request_id,
                        verified_execution.intent_digest,
                        execution_authority_digest(verified_execution),
                        verified_execution.policy_digest,
                        verified_execution.authority_grant_id,
                        verified_execution.authority_lease_id,
                        verified_execution.authority_chain_digest,
                        ExecutionState.RESERVED.value,
                        reserved_at.isoformat(),
                    ),
                )
                c.execute("COMMIT")
                return None
            except sqlite3.IntegrityError:
                c.execute("ROLLBACK")

        if verified_execution.authority_lease_id is not None:
            lease = self.get_capability_lease(verified_execution.authority_lease_id)
            if (
                lease is None
                or lease.grant_id != verified_execution.authority_grant_id
                or lease.status != CapabilityLeaseStatus.ACTIVE
                or lease.remaining_uses < 1
                or lease.expires_at <= reserved_at
            ):
                return "authority.lease_unavailable"

        with self._connect() as c:
            authority_conflict = c.execute(
                """
                SELECT 1 FROM consumed_nonces WHERE nonce = ? OR decision_id = ? LIMIT 1
                """,
                (verified_execution.nonce, verified_execution.decision_id),
            ).fetchone()
            if authority_conflict is not None:
                return "decision_receipt.replayed"
            execution_conflict = c.execute(
                "SELECT 1 FROM executions WHERE execution_id = ? LIMIT 1",
                (verified_execution.execution_id,),
            ).fetchone()
            if execution_conflict is not None:
                return "execution.id_conflict"
        return "execution.reservation_conflict"

    def mark_execution_dispatching(
        self,
        execution_id: str,
        dispatching_at: datetime,
    ) -> ExecutionRecord:
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            result = c.execute(
                """
                UPDATE executions
                SET state = ?, dispatching_at = ?
                WHERE execution_id = ? AND state = ?
                """,
                (
                    ExecutionState.DISPATCHING.value,
                    dispatching_at.isoformat(),
                    execution_id,
                    ExecutionState.RESERVED.value,
                ),
            )
            if result.rowcount != 1:
                c.execute("ROLLBACK")
                raise RuntimeError("execution.not_reserved")
            c.execute("COMMIT")
        record = self.get_execution(execution_id)
        if record is None:
            raise RuntimeError("execution.record_missing")
        return record

    def finish_execution(
        self,
        execution_id: str,
        terminal_state: ExecutionState,
        *,
        completed_at: datetime,
        provider_status: int | None = None,
        result_digest: str | None = None,
        error_code: str | None = None,
    ) -> ExecutionRecord:
        if terminal_state not in _TERMINAL_STATES:
            raise ValueError("execution.terminal_state_required")
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            result = c.execute(
                """
                UPDATE executions
                SET state = ?, completed_at = ?, provider_status = ?,
                    result_digest = ?, error_code = ?
                WHERE execution_id = ? AND state = ?
                """,
                (
                    terminal_state.value,
                    completed_at.isoformat(),
                    provider_status,
                    result_digest,
                    error_code,
                    execution_id,
                    ExecutionState.DISPATCHING.value,
                ),
            )
            if result.rowcount != 1:
                c.execute("ROLLBACK")
                raise RuntimeError("execution.not_dispatching")
            c.execute("COMMIT")
        record = self.get_execution(execution_id)
        if record is None:
            raise RuntimeError("execution.record_missing")
        return record

    def get_execution(self, execution_id: str) -> ExecutionRecord | None:
        with self._connect() as c:
            row = c.execute(
                """
                SELECT execution_id,decision_id,trace_id,request_id,intent_digest,
                       authority_digest,policy_digest,authority_grant_id,authority_lease_id,
                       authority_chain_digest,state,reserved_at,dispatching_at,completed_at,
                       provider_status,result_digest,error_code
                FROM executions WHERE execution_id = ?
                """,
                (execution_id,),
            ).fetchone()
        return self._execution_record(row) if row is not None else None

    def list_executions(self) -> tuple[ExecutionRecord, ...]:
        with self._connect() as c:
            rows = c.execute(
                """
                SELECT execution_id,decision_id,trace_id,request_id,intent_digest,
                       authority_digest,policy_digest,authority_grant_id,authority_lease_id,
                       authority_chain_digest,state,reserved_at,dispatching_at,completed_at,
                       provider_status,result_digest,error_code
                FROM executions ORDER BY reserved_at, execution_id
                """
            ).fetchall()
        return tuple(self._execution_record(row) for row in rows)

    def recover_incomplete_executions(self, recovered_at: datetime) -> tuple[ExecutionRecord, ...]:
        """Conservatively terminalize stranded DISPATCHING executions as UNKNOWN.

        RESERVED records are intentionally left untouched because no external dispatch had begun.
        Terminal records are immutable and are never re-dispatched by recovery.
        """

        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            rows = c.execute(
                "SELECT execution_id FROM executions WHERE state = ? ORDER BY reserved_at",
                (ExecutionState.DISPATCHING.value,),
            ).fetchall()
            ids = [str(row[0]) for row in rows]
            if ids:
                c.executemany(
                    """
                    UPDATE executions
                    SET state = ?, completed_at = ?, error_code = ?
                    WHERE execution_id = ? AND state = ?
                    """,
                    [
                        (
                            ExecutionState.UNKNOWN.value,
                            recovered_at.isoformat(),
                            "execution.recovered_ambiguous_dispatch",
                            execution_id,
                            ExecutionState.DISPATCHING.value,
                        )
                        for execution_id in ids
                    ],
                )
            c.execute("COMMIT")
        records = [self.get_execution(execution_id) for execution_id in ids]
        return tuple(record for record in records if record is not None)

    def record_execution_resolution(
        self,
        execution_id: str,
        evidence: ReconciliationEvidence,
        reconciled_at: datetime,
    ) -> ExecutionResolution:
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                execution_row = c.execute(
                    "SELECT state FROM executions WHERE execution_id = ?",
                    (execution_id,),
                ).fetchone()
                if execution_row is None:
                    raise RuntimeError("execution.record_missing")
                execution_state = ExecutionState(str(execution_row[0]))
                if execution_state != ExecutionState.UNKNOWN:
                    raise RuntimeError("reconciliation.execution_not_unknown")

                existing_row = c.execute(
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
                    c.execute("COMMIT")
                    return existing
                if (
                    existing is not None
                    and existing.status == evidence.status
                    and existing.evidence_digest == evidence.evidence_digest
                    and existing.trust_level == evidence.trust_level
                ):
                    c.execute("COMMIT")
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
                    c.execute("COMMIT")
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
                c.execute(
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
                c.execute("COMMIT")
                return resolution
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise

    @staticmethod
    def _resolution(row: sqlite3.Row | tuple[object, ...]) -> ExecutionResolution:
        return ExecutionResolution(
            resolution_id=str(row[0]),
            execution_id=str(row[1]),
            original_state=ExecutionState(str(row[2])),
            status=ReconciliationStatus(str(row[3])),
            source=str(row[4]),
            evidence_digest=str(row[5]),
            trust_level=EvidenceTrustLevel(str(row[6])),
            provider_operation_id_digest=str(row[7]) if row[7] is not None else None,
            observed_at=datetime.fromisoformat(str(row[8])),
            reconciled_at=datetime.fromisoformat(str(row[9])),
            error_code=str(row[10]) if row[10] is not None else None,
        )

    def list_execution_resolutions(self, execution_id: str) -> tuple[ExecutionResolution, ...]:
        with self._connect() as c:
            rows = c.execute(
                """
                SELECT resolution_id,execution_id,original_state,status,source,evidence_digest,
                       trust_level,provider_operation_id_digest,observed_at,reconciled_at,error_code
                FROM execution_resolutions WHERE execution_id = ? ORDER BY sequence
                """,
                (execution_id,),
            ).fetchall()
        return tuple(self._resolution(row) for row in rows)

    def get_latest_execution_resolution(self, execution_id: str) -> ExecutionResolution | None:
        with self._connect() as c:
            row = c.execute(
                """
                SELECT resolution_id,execution_id,original_state,status,source,evidence_digest,
                       trust_level,provider_operation_id_digest,observed_at,reconciled_at,error_code
                FROM execution_resolutions WHERE execution_id = ? ORDER BY sequence DESC LIMIT 1
                """,
                (execution_id,),
            ).fetchone()
        return self._resolution(row) if row is not None else None

    def record_attestation_metadata(self, metadata: AttestationMetadata) -> None:
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                row = c.execute(
                    """
                    SELECT payload_digest FROM execution_attestations
                    WHERE execution_id = ? ORDER BY rowid DESC LIMIT 1
                    """,
                    (metadata.execution_id,),
                ).fetchone()
                current_head = str(row[0]) if row is not None else None
                if metadata.previous_attestation_digest != current_head:
                    raise RuntimeError("attestation.chain_head_changed")
                c.execute(
                    """
                    INSERT INTO execution_attestations(
                        attestation_id,execution_id,payload_digest,signature_digest,signer_key_id,
                        previous_attestation_digest,issued_at
                    ) VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        metadata.attestation_id,
                        metadata.execution_id,
                        metadata.payload_digest,
                        metadata.signature_digest,
                        metadata.signer_key_id,
                        metadata.previous_attestation_digest,
                        metadata.issued_at.isoformat(),
                    ),
                )
                c.execute("COMMIT")
            except Exception:
                if c.in_transaction:
                    c.execute("ROLLBACK")
                raise

    def get_latest_attestation_metadata(self, execution_id: str) -> AttestationMetadata | None:
        with self._connect() as c:
            row = c.execute(
                """
                SELECT attestation_id,execution_id,payload_digest,signature_digest,signer_key_id,
                       previous_attestation_digest,issued_at
                FROM execution_attestations
                WHERE execution_id = ? ORDER BY rowid DESC LIMIT 1
                """,
                (execution_id,),
            ).fetchone()
        if row is None:
            return None
        return AttestationMetadata(
            attestation_id=str(row[0]),
            execution_id=str(row[1]),
            payload_digest=str(row[2]),
            signature_digest=str(row[3]),
            signer_key_id=str(row[4]),
            previous_attestation_digest=str(row[5]) if row[5] is not None else None,
            issued_at=datetime.fromisoformat(str(row[6])),
        )

    def store_authority_grant(self, grant: AuthorityGrant) -> None:
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            if grant.parent_grant_id is not None:
                allocation = c.execute(
                    """
                    UPDATE authority_grants
                    SET remaining_calls = remaining_calls - ?
                    WHERE grant_id = ?
                      AND status = ?
                      AND expires_at > ?
                      AND remaining_calls >= ?
                    """,
                    (
                        grant.scope.maximum_calls,
                        grant.parent_grant_id,
                        AuthorityGrantStatus.ACTIVE.value,
                        grant.issued_at.isoformat(),
                        grant.scope.maximum_calls,
                    ),
                )
                if allocation.rowcount != 1:
                    c.execute("ROLLBACK")
                    raise RuntimeError("authority.call_budget_exhausted")
            c.execute(
                """
                INSERT INTO authority_grants(
                    grant_id,parent_grant_id,grant_json,status,remaining_calls,expires_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    grant.grant_id,
                    grant.parent_grant_id,
                    grant.model_dump_json(),
                    AuthorityGrantStatus.ACTIVE.value,
                    grant.scope.maximum_calls,
                    grant.expires_at.isoformat(),
                ),
            )
            c.execute("COMMIT")

    def get_authority_grant(self, grant_id: str) -> AuthorityGrantRecord | None:
        with self._connect() as c:
            row = c.execute(
                """
                SELECT grant_json,status,remaining_calls,revoked_at,revoke_reason
                FROM authority_grants WHERE grant_id = ?
                """,
                (grant_id,),
            ).fetchone()
        if row is None:
            return None
        return AuthorityGrantRecord(
            grant=AuthorityGrant.model_validate_json(str(row[0])),
            status=AuthorityGrantStatus(str(row[1])),
            remaining_calls=int(row[2]),
            revoked_at=datetime.fromisoformat(str(row[3])) if row[3] is not None else None,
            revoke_reason=str(row[4]) if row[4] is not None else None,
        )

    def revoke_authority_grant(
        self, grant_id: str, revoked_at: datetime, reason: str
    ) -> AuthorityGrantRecord:
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            active = c.execute(
                "SELECT 1 FROM authority_grants WHERE grant_id = ? AND status = ?",
                (grant_id, AuthorityGrantStatus.ACTIVE.value),
            ).fetchone()
            if active is None:
                c.execute("ROLLBACK")
                raise RuntimeError("authority.grant_not_active")
            descendants = c.execute(
                """
                WITH RECURSIVE descendants(grant_id) AS (
                    SELECT grant_id FROM authority_grants WHERE grant_id = ?
                    UNION ALL
                    SELECT g.grant_id FROM authority_grants g
                    JOIN descendants d ON g.parent_grant_id = d.grant_id
                )
                SELECT grant_id FROM descendants
                """,
                (grant_id,),
            ).fetchall()
            ids = [str(row[0]) for row in descendants]
            placeholders = ",".join("?" for _ in ids)
            c.execute(
                f"""
                UPDATE authority_grants
                SET status = ?, revoked_at = ?, revoke_reason = ?
                WHERE grant_id IN ({placeholders}) AND status = ?
                """,
                (
                    AuthorityGrantStatus.REVOKED.value,
                    revoked_at.isoformat(),
                    reason,
                    *ids,
                    AuthorityGrantStatus.ACTIVE.value,
                ),
            )
            c.execute(
                f"""
                UPDATE capability_leases SET status = ?
                WHERE grant_id IN ({placeholders}) AND status = ?
                """,
                (
                    CapabilityLeaseStatus.REVOKED.value,
                    *ids,
                    CapabilityLeaseStatus.ACTIVE.value,
                ),
            )
            c.execute("COMMIT")
        record = self.get_authority_grant(grant_id)
        if record is None:
            raise RuntimeError("authority.grant_missing")
        return record

    def store_capability_lease(self, lease: CapabilityLease) -> None:
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            allocation = c.execute(
                """
                UPDATE authority_grants
                SET remaining_calls = remaining_calls - ?
                WHERE grant_id = ?
                  AND status = ?
                  AND expires_at >= ?
                  AND remaining_calls >= ?
                """,
                (
                    lease.maximum_uses,
                    lease.grant_id,
                    AuthorityGrantStatus.ACTIVE.value,
                    lease.expires_at.isoformat(),
                    lease.maximum_uses,
                ),
            )
            if allocation.rowcount != 1:
                c.execute("ROLLBACK")
                raise RuntimeError("authority.call_budget_exhausted")
            c.execute(
                """
                INSERT INTO capability_leases(
                    lease_id,grant_id,maximum_uses,remaining_uses,issued_at,expires_at,status
                ) VALUES(?,?,?,?,?,?,?)
                """,
                (
                    lease.lease_id,
                    lease.grant_id,
                    lease.maximum_uses,
                    lease.remaining_uses,
                    lease.issued_at.isoformat(),
                    lease.expires_at.isoformat(),
                    lease.status.value,
                ),
            )
            c.execute("COMMIT")

    def get_capability_lease(self, lease_id: str) -> CapabilityLease | None:
        with self._connect() as c:
            row = c.execute(
                """
                SELECT lease_id,grant_id,maximum_uses,remaining_uses,issued_at,expires_at,status
                FROM capability_leases WHERE lease_id = ?
                """,
                (lease_id,),
            ).fetchone()
        if row is None:
            return None
        return CapabilityLease(
            lease_id=str(row[0]),
            grant_id=str(row[1]),
            maximum_uses=int(row[2]),
            remaining_uses=int(row[3]),
            issued_at=datetime.fromisoformat(str(row[4])),
            expires_at=datetime.fromisoformat(str(row[5])),
            status=CapabilityLeaseStatus(str(row[6])),
        )

    def revoke_capability_lease(self, lease_id: str, revoked_at: datetime) -> CapabilityLease:
        del revoked_at
        with self._connect() as c:
            result = c.execute(
                """
                UPDATE capability_leases SET status = ?
                WHERE lease_id = ? AND status = ?
                """,
                (
                    CapabilityLeaseStatus.REVOKED.value,
                    lease_id,
                    CapabilityLeaseStatus.ACTIVE.value,
                ),
            )
            if result.rowcount != 1:
                raise RuntimeError("authority.lease_not_active")
        lease = self.get_capability_lease(lease_id)
        if lease is None:
            raise RuntimeError("authority.lease_missing")
        return lease

    def register_approval(self, approval: ApprovalReceipt) -> None:
        with self._connect() as c:
            c.execute(
                """
                INSERT INTO approvals(
                    approval_id,decision_id,receipt_json,used_count,maximum_uses,expires_at
                ) VALUES(?,?,?,?,?,?)
                """,
                (
                    approval.approval_id,
                    approval.decision_id,
                    approval.model_dump_json(),
                    0,
                    approval.maximum_uses,
                    approval.expires_at.isoformat(),
                ),
            )

    def claim_credential_issuance(
        self,
        *,
        request_id: str,
        decision_id: str,
        approval_id: str | None,
        single_use: bool,
        claimed_at: datetime,
    ) -> str | None:
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            try:
                c.execute(
                    """
                    INSERT INTO credential_issuance_claims(
                        request_id,decision_id,approval_id,single_use,status,claimed_at
                    ) VALUES(?,?,?,?,?,?)
                    """,
                    (
                        request_id,
                        decision_id,
                        approval_id,
                        int(single_use),
                        "pending",
                        claimed_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError:
                c.execute("ROLLBACK")
                return "credential.issuance_already_consumed"
            if approval_id is not None:
                row = c.execute(
                    """
                    SELECT decision_id,used_count,maximum_uses,expires_at
                    FROM approvals WHERE approval_id = ?
                    """,
                    (approval_id,),
                ).fetchone()
                if row is None or str(row[0]) != decision_id:
                    c.execute("ROLLBACK")
                    return "credential.approval_not_registered"
                if datetime.fromisoformat(str(row[3])) <= claimed_at:
                    c.execute("ROLLBACK")
                    return "credential.approval_expired"
                if int(row[1]) >= int(row[2]):
                    c.execute("ROLLBACK")
                    return "credential.approval_exhausted"
                updated = c.execute(
                    """
                    UPDATE approvals SET used_count = used_count + 1
                    WHERE approval_id = ? AND used_count < maximum_uses
                    """,
                    (approval_id,),
                )
                if updated.rowcount != 1:
                    c.execute("ROLLBACK")
                    return "credential.approval_exhausted"
            c.execute("COMMIT")
            return None

    def finish_credential_issuance(
        self,
        request_id: str,
        issuance_id: str | None,
        *,
        succeeded: bool,
        completed_at: datetime,
    ) -> None:
        with self._connect() as c:
            result = c.execute(
                """
                UPDATE credential_issuance_claims
                SET status = ?, issuance_id = ?, completed_at = ?
                WHERE request_id = ? AND status = 'pending'
                """,
                (
                    "succeeded" if succeeded else "failed",
                    issuance_id,
                    completed_at.isoformat(),
                    request_id,
                ),
            )
            if result.rowcount != 1:
                raise RuntimeError("credential.issuance_claim_not_pending")

    def append(self, event: AuditEvent) -> AuditEvent:
        with self._connect() as c:
            c.execute("BEGIN IMMEDIATE")
            row = c.execute(
                "SELECT sequence,event_hash FROM audit_events ORDER BY sequence DESC LIMIT 1"
            ).fetchone()
            previous = row[1] if row else GENESIS
            sequence = (row[0] + 1) if row else 1
            base = event.model_copy(
                update={"sequence": sequence, "previous_hash": previous, "event_hash": None}
            )
            event_hash = sha256(previous.encode() + canonical_bytes(base)).hexdigest()
            complete = base.model_copy(update={"event_hash": event_hash})
            c.execute(
                """
                INSERT INTO audit_events(event_id,event_json,previous_hash,event_hash)
                VALUES(?,?,?,?)
                """,
                (complete.event_id, complete.model_dump_json(), previous, event_hash),
            )
            c.execute("COMMIT")
            return complete

    def list_events(self) -> list[AuditEvent]:
        with self._connect() as c:
            rows = c.execute("SELECT event_json FROM audit_events ORDER BY sequence").fetchall()
        return [AuditEvent.model_validate_json(r[0]) for r in rows]

    def audit_head_at(self, event_count: int) -> str | None:
        if event_count < 0:
            raise ValueError("event_count cannot be negative")
        if event_count == 0:
            return GENESIS
        with self._connect() as c:
            row = c.execute(
                "SELECT event_hash FROM audit_events WHERE sequence = ?",
                (event_count,),
            ).fetchone()
        return str(row[0]) if row is not None else None

    def verify(self) -> tuple[bool, int, str, str | None]:
        previous = GENESIS
        count = 0
        for event in self.list_events():
            count += 1
            if event.previous_hash != previous:
                return False, count, previous, "audit.previous_hash_mismatch"
            base = event.model_copy(update={"event_hash": None})
            expected = sha256(previous.encode() + canonical_bytes(base)).hexdigest()
            if event.event_hash != expected:
                return False, count, previous, "audit.event_hash_mismatch"
            previous = expected
        return True, count, previous, None
