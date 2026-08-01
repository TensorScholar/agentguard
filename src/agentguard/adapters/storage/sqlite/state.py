from __future__ import annotations

import sqlite3
from datetime import datetime
from hashlib import sha256
from pathlib import Path

from agentguard.domain import ApprovalReceipt, AuditEvent
from agentguard.engine.canonical import canonical_bytes
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
CREATE TABLE IF NOT EXISTS agentguard_schema(
 component TEXT PRIMARY KEY, version INTEGER NOT NULL
);
INSERT OR IGNORE INTO agentguard_schema(component, version) VALUES('action_integrity', 3);
UPDATE agentguard_schema SET version = 3 WHERE component = 'action_integrity';
"""

V2_AUDIT_COLUMNS = {
    "sequence",
    "event_id",
    "event_json",
    "previous_hash",
    "event_hash",
}


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

    def _connect(self) -> sqlite3.Connection:
        c = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        c.execute("PRAGMA busy_timeout=10000")
        c.execute("PRAGMA foreign_keys=ON")
        c.execute("PRAGMA trusted_schema=OFF")
        c.execute("PRAGMA synchronous=FULL")
        c.execute("PRAGMA secure_delete=ON")
        return c

    def consume(self, nonce: str, decision_id: str, consumed_at: datetime) -> bool:
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
