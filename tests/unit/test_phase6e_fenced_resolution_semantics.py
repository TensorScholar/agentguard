from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta

from agentguard.adapters.storage.sqlite import SQLiteFencedReconciliationState
from agentguard.domain import (
    EvidenceTrustLevel,
    ReconciliationEvidence,
    ReconciliationStatus,
)

NOW = datetime(2026, 9, 2, 20, 0, tzinfo=UTC)


def _insert_unknown(path) -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO executions(
                execution_id,decision_id,nonce,trace_id,request_id,intent_digest,
                authority_digest,state,reserved_at,dispatching_at,completed_at,error_code
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                "exec_semantics",
                "decision_semantics",
                "nonce_semantics",
                "trace_semantics",
                "request_semantics",
                "sha256:" + "1" * 64,
                "sha256:" + "2" * 64,
                "unknown",
                (NOW - timedelta(seconds=2)).isoformat(),
                (NOW - timedelta(seconds=1)).isoformat(),
                NOW.isoformat(),
                "execution.outcome_ambiguous",
            ),
        )


def _evidence(status: ReconciliationStatus, marker: str) -> ReconciliationEvidence:
    return ReconciliationEvidence(
        status=status,
        source="provider-status",
        evidence_digest="sha256:" + marker * 64,
        trust_level=EvidenceTrustLevel.PROVIDER_VERIFIED,
        observed_at=NOW + timedelta(seconds=1),
    )


def _resolve(
    state: SQLiteFencedReconciliationState,
    evidence: ReconciliationEvidence,
    *,
    offset: int,
):
    now = NOW + timedelta(seconds=offset)
    lease = state.claim_reconciliation_lease(
        "exec_semantics",
        f"worker-{offset}",
        now=now,
        lease_seconds=30,
    )
    assert lease is not None
    with state.resolution_lease(lease):
        resolution = state.record_execution_resolution(
            "exec_semantics",
            evidence,
            now + timedelta(seconds=1),
        )
    assert state.get_reconciliation_lease("exec_semantics") is None
    return resolution


def test_duplicate_evidence_preserves_existing_resolution_under_fence(tmp_path) -> None:
    state = SQLiteFencedReconciliationState(tmp_path / "state.sqlite")
    _insert_unknown(state.path)
    evidence = _evidence(ReconciliationStatus.STILL_UNKNOWN, "3")

    first = _resolve(state, evidence, offset=2)
    second = _resolve(state, evidence, offset=4)

    assert second == first
    assert len(state.list_execution_resolutions("exec_semantics")) == 1


def test_terminal_resolution_is_not_downgraded_by_unknown_evidence(tmp_path) -> None:
    state = SQLiteFencedReconciliationState(tmp_path / "state.sqlite")
    _insert_unknown(state.path)
    succeeded = _evidence(ReconciliationStatus.CONFIRMED_SUCCEEDED, "4")
    unknown = _evidence(ReconciliationStatus.STILL_UNKNOWN, "5")

    terminal = _resolve(state, succeeded, offset=2)
    preserved = _resolve(state, unknown, offset=4)

    assert preserved == terminal
    assert preserved.status == ReconciliationStatus.CONFIRMED_SUCCEEDED
    assert len(state.list_execution_resolutions("exec_semantics")) == 1


def test_conflicting_terminal_provider_evidence_becomes_agentguard_conflict(tmp_path) -> None:
    state = SQLiteFencedReconciliationState(tmp_path / "state.sqlite")
    _insert_unknown(state.path)
    succeeded = _evidence(ReconciliationStatus.CONFIRMED_SUCCEEDED, "6")
    failed = _evidence(ReconciliationStatus.CONFIRMED_FAILED, "7")

    first = _resolve(state, succeeded, offset=2)
    conflict = _resolve(state, failed, offset=4)

    assert first.status == ReconciliationStatus.CONFIRMED_SUCCEEDED
    assert conflict.status == ReconciliationStatus.CONFLICT
    assert conflict.source == "agentguard"
    assert conflict.trust_level == EvidenceTrustLevel.AGENTGUARD_SIGNED
    assert conflict.error_code == "reconciliation.conflicting_evidence"
    assert len(state.list_execution_resolutions("exec_semantics")) == 2

    replay = _resolve(state, failed, offset=6)
    assert replay == conflict
    assert len(state.list_execution_resolutions("exec_semantics")) == 2
