from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import pytest

from agentguard.adapters.storage.sqlite import (
    IncompatibleStateDatabaseError,
    SQLiteState,
)
from agentguard.audit import AuditLedger
from agentguard.domain import AuditEvent, AuditEventType


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
