from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from decisionlock.adapters.storage.sqlite import (
    IncompatibleStateDatabaseError,
    SQLiteState,
)
from decisionlock.audit import AuditLedger
from decisionlock.domain import AuditEvent, AuditEventType


def test_nonce_single_use(state):
    now = datetime.now(UTC)
    assert state.consume("n", "d", now) is True
    assert state.consume("n", "d", now) is False


def test_nonce_concurrency_only_one_wins(state):
    now = datetime.now(UTC)
    with ThreadPoolExecutor(max_workers=8) as ex:
        results = list(ex.map(lambda _: state.consume("same", "d", now), range(20)))
    assert sum(results) == 1


def test_audit_chain_verifies(state):
    for i in range(3):
        state.append(
            AuditEvent(
                event_id=f"e{i}",
                event_type=AuditEventType.AUTHORIZATION_REQUESTED,
                timestamp=datetime.now(UTC),
                trace_id="t",
                source="test",
            )
        )
    ok, count, head, reason = state.verify()
    assert ok and count == 3 and len(head) == 64 and reason is None


def test_audit_tamper_detected(state):
    state.append(
        AuditEvent(
            event_id="e",
            event_type=AuditEventType.AUTHORIZATION_REQUESTED,
            timestamp=datetime.now(UTC),
            trace_id="t",
            source="test",
        )
    )
    import sqlite3

    with sqlite3.connect(state.path) as c:
        c.execute(
            "UPDATE audit_events SET event_json = replace(event_json,'authorization.requested','execution.succeeded')"
        )
    ok, _, _, reason = state.verify()
    assert not ok and reason == "audit.event_hash_mismatch"


def test_existing_v1_audit_database_is_never_overwritten(tmp_path: Path) -> None:
    path = tmp_path / "v1-audit.sqlite"
    AuditLedger(path)

    with pytest.raises(IncompatibleStateDatabaseError, match="retain it as v0.1 evidence"):
        SQLiteState(path)

    assert "arguments_json" in path.read_bytes().decode("latin-1")


def test_existing_v2_action_integrity_schema_upgrades_in_place(tmp_path: Path) -> None:
    import sqlite3

    path = tmp_path / "v2-state.sqlite"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE audit_events(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                event_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            );
            CREATE TABLE decisionlock_schema(
                component TEXT PRIMARY KEY,
                version INTEGER NOT NULL
            );
            INSERT INTO decisionlock_schema(component, version)
            VALUES('action_integrity', 3);
            """
        )

    state = SQLiteState(path)
    with sqlite3.connect(state.path) as connection:
        version = connection.execute(
            "SELECT version FROM decisionlock_schema WHERE component = 'action_integrity'"
        ).fetchone()
        execution_table = connection.execute(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'executions'"
        ).fetchone()

    assert version == (9,)
    assert execution_table == ("executions",)


def test_phase5cd_migrates_existing_v4_execution_columns_without_losing_state(
    tmp_path: Path,
) -> None:
    import sqlite3

    path = tmp_path / "v4-state.sqlite"
    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE audit_events(
                sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                event_id TEXT UNIQUE NOT NULL,
                event_json TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            );
            CREATE TABLE executions(
                execution_id TEXT PRIMARY KEY,
                decision_id TEXT UNIQUE NOT NULL,
                nonce TEXT UNIQUE NOT NULL,
                trace_id TEXT NOT NULL,
                request_id TEXT NOT NULL,
                intent_digest TEXT NOT NULL,
                authority_digest TEXT NOT NULL,
                state TEXT NOT NULL,
                reserved_at TEXT NOT NULL,
                dispatching_at TEXT,
                completed_at TEXT,
                provider_status INTEGER,
                result_digest TEXT,
                error_code TEXT
            );
            INSERT INTO executions(
                execution_id,decision_id,nonce,trace_id,request_id,intent_digest,
                authority_digest,state,reserved_at,dispatching_at,completed_at,
                provider_status,result_digest,error_code
            ) VALUES(
                'exec-existing','decision-existing','nonce-existing','trace-existing',
                'request-existing',
                'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
                'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
                'unknown','2026-08-29T10:00:00+00:00',NULL,'2026-08-29T10:00:01+00:00',
                NULL,NULL,'execution.test_unknown'
            );
            CREATE TABLE decisionlock_schema(
                component TEXT PRIMARY KEY,
                version INTEGER NOT NULL
            );
            INSERT INTO decisionlock_schema(component, version)
            VALUES('action_integrity', 4);
            """
        )

    state = SQLiteState(path)
    with sqlite3.connect(state.path) as connection:
        columns = {row[1] for row in connection.execute("PRAGMA table_info(executions)").fetchall()}
        version = connection.execute(
            "SELECT version FROM decisionlock_schema WHERE component = 'action_integrity'"
        ).fetchone()

    existing = state.get_execution("exec-existing")
    assert existing is not None
    assert existing.execution_id == "exec-existing"
    assert existing.decision_id == "decision-existing"
    assert existing.state.value == "unknown"
    assert existing.error_code == "execution.test_unknown"
    assert existing.policy_digest is None
    assert existing.authority_grant_id is None
    assert existing.authority_lease_id is None
    assert existing.authority_chain_digest is None
    assert existing.tenant_id is None
    assert existing.principal_digest is None
    assert existing.subject_digest is None
    assert existing.field_integrity_digest is None
    assert existing.field_release_set_digest is None
    assert existing.field_integrity_expires_at is None
    assert existing.causal_digest is None
    assert existing.causal_depth == 0
    assert existing.causal_labels == frozenset()
    assert existing.causal_parent_execution_ids == ()
    assert existing.prepared_id is None
    assert version == (9,)
    assert {
        "policy_digest",
        "authority_grant_id",
        "authority_lease_id",
        "authority_chain_digest",
        "tenant_id",
        "principal_digest",
        "subject_digest",
        "field_integrity_digest",
        "field_release_set_digest",
        "field_integrity_expires_at",
        "causal_digest",
        "causal_depth",
        "causal_labels_json",
        "causal_parent_ids_json",
        "prepared_id",
    } <= columns
    with sqlite3.connect(state.path) as connection:
        new_tables = {
            row[0]
            for row in connection.execute(
                "SELECT name FROM sqlite_master WHERE type='table'"
            ).fetchall()
        }
    assert {"consumed_field_releases", "prepared_executions"} <= new_tables
