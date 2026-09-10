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


def _insert_unknown(path, execution_id: str = "exec_semantics") -> None:
    with sqlite3.connect(path) as connection:
        connection.execute(
            """
            INSERT INTO executions(
                execution_id,decision_id,nonce,trace_id,request_id,intent_digest,
                authority_digest,state,reserved_at,dispatching_at,completed_at,error_code
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                execution_id,
                f"decision_{execution_id}",
                f"nonce_{execution_id}",
                f"trace_{execution_id}",
                f"request_{execution_id}",
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
    execution_id: str = "exec_semantics",
    allow_terminal_recheck: bool = False,
):
    now = NOW + timedelta(seconds=offset)
    lease = state.claim_reconciliation_lease(
        execution_id,
        f"worker-{offset}",
        now=now,
        lease_seconds=30,
        allow_terminal_recheck=allow_terminal_recheck,
    )
    assert lease is not None
    with state.resolution_lease(lease):
        resolution = state.record_execution_resolution(
            execution_id,
            evidence,
            now + timedelta(seconds=1),
        )
    assert state.get_reconciliation_lease(execution_id) is None
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
    assert terminal.status == ReconciliationStatus.CONFIRMED_SUCCEEDED

    # Q04-03 Invariant A: CONFIRMED_SUCCEEDED cannot acquire default reconciliation lease
    assert (
        state.claim_reconciliation_lease(
            "exec_semantics", "worker-4", now=NOW + timedelta(seconds=4), lease_seconds=30
        )
        is None
    )

    # Invariant D: Explicit operator re-check CAN acquire lease, but record_execution_resolution will not downgrade
    preserved = _resolve(state, unknown, offset=4, allow_terminal_recheck=True)

    assert preserved == terminal
    assert preserved.status == ReconciliationStatus.CONFIRMED_SUCCEEDED
    assert len(state.list_execution_resolutions("exec_semantics")) == 1


def test_conflicting_terminal_provider_evidence_becomes_agentguard_conflict(tmp_path) -> None:
    state = SQLiteFencedReconciliationState(tmp_path / "state.sqlite")
    _insert_unknown(state.path)
    succeeded = _evidence(ReconciliationStatus.CONFIRMED_SUCCEEDED, "6")
    failed = _evidence(ReconciliationStatus.CONFIRMED_FAILED, "7")

    first = _resolve(state, succeeded, offset=2)
    assert first.status == ReconciliationStatus.CONFIRMED_SUCCEEDED

    # Q04-03 Invariant A: CONFIRMED_SUCCEEDED cannot acquire default reconciliation lease
    assert (
        state.claim_reconciliation_lease(
            "exec_semantics", "worker-4", now=NOW + timedelta(seconds=4), lease_seconds=30
        )
        is None
    )

    # Invariant D & F: Under explicit operator re-check lease, conflicting terminal evidence synthesizes CONFLICT
    conflict = _resolve(state, failed, offset=4, allow_terminal_recheck=True)

    assert first.status == ReconciliationStatus.CONFIRMED_SUCCEEDED
    assert conflict.status == ReconciliationStatus.CONFLICT
    assert conflict.source == "agentguard"
    assert conflict.trust_level == EvidenceTrustLevel.AGENTGUARD_SIGNED
    assert conflict.error_code == "reconciliation.conflicting_evidence"
    assert len(state.list_execution_resolutions("exec_semantics")) == 2

    # Invariant C & G: Once CONFLICT exists, both default and explicit operator recheck reject lease acquisition
    assert (
        state.claim_reconciliation_lease(
            "exec_semantics", "worker-6", now=NOW + timedelta(seconds=6), lease_seconds=30
        )
        is None
    )
    assert (
        state.claim_reconciliation_lease(
            "exec_semantics",
            "operator-6",
            now=NOW + timedelta(seconds=6),
            lease_seconds=30,
            allow_terminal_recheck=True,
        )
        is None
    )


def test_confirmed_succeeded_rejected_by_default_lease_allowed_by_operator_recheck(
    tmp_path,
) -> None:
    """Proves Invariant A (default lease rejects CONFIRMED_SUCCEEDED) and Invariant D (operator recheck allows it)."""
    state = SQLiteFencedReconciliationState(tmp_path / "state.sqlite")
    now = NOW + timedelta(seconds=10)
    _insert_unknown(state.path, "exec_succ")
    _resolve(
        state,
        _evidence(ReconciliationStatus.CONFIRMED_SUCCEEDED, "a"),
        offset=2,
        execution_id="exec_succ",
    )
    # Default lease acquisition rejects CONFIRMED_SUCCEEDED (Invariant A)
    assert (
        state.claim_reconciliation_lease("exec_succ", "worker-contender", now=now, lease_seconds=30)
        is None
    )
    # Explicit operator re-check allows CONFIRMED_SUCCEEDED (Invariant D)
    succ_lease = state.claim_reconciliation_lease(
        "exec_succ", "operator-contender", now=now, lease_seconds=30, allow_terminal_recheck=True
    )
    assert succ_lease is not None
    state.release_reconciliation_lease(succ_lease)


def test_confirmed_failed_rejected_by_default_lease_allowed_by_operator_recheck(
    tmp_path,
) -> None:
    """Proves Invariant B (default lease rejects CONFIRMED_FAILED) and Invariant E (operator recheck allows it)."""
    state = SQLiteFencedReconciliationState(tmp_path / "state.sqlite")
    now = NOW + timedelta(seconds=10)
    _insert_unknown(state.path, "exec_fail")
    _resolve(
        state,
        _evidence(ReconciliationStatus.CONFIRMED_FAILED, "b"),
        offset=2,
        execution_id="exec_fail",
    )
    # Default lease acquisition rejects CONFIRMED_FAILED (Invariant B)
    assert (
        state.claim_reconciliation_lease("exec_fail", "worker-contender", now=now, lease_seconds=30)
        is None
    )
    # Explicit operator re-check allows CONFIRMED_FAILED (Invariant E)
    fail_lease = state.claim_reconciliation_lease(
        "exec_fail", "operator-contender", now=now, lease_seconds=30, allow_terminal_recheck=True
    )
    assert fail_lease is not None
    state.release_reconciliation_lease(fail_lease)


def test_conflict_rejected_by_both_default_lease_and_operator_recheck(tmp_path) -> None:
    """Proves Invariant C (default lease rejects CONFLICT) and Invariant G (operator recheck also rejects CONFLICT)."""
    state = SQLiteFencedReconciliationState(tmp_path / "state.sqlite")
    now = NOW + timedelta(seconds=10)
    _insert_unknown(state.path, "exec_conf")
    _resolve(
        state,
        _evidence(ReconciliationStatus.CONFIRMED_SUCCEEDED, "c"),
        offset=2,
        execution_id="exec_conf",
    )
    # Synthesize conflict using explicit operator recheck (Invariant F)
    conflict_res = _resolve(
        state,
        _evidence(ReconciliationStatus.CONFIRMED_FAILED, "d"),
        offset=4,
        execution_id="exec_conf",
        allow_terminal_recheck=True,
    )
    assert conflict_res.status == ReconciliationStatus.CONFLICT
    latest = state.get_latest_execution_resolution("exec_conf")
    assert latest is not None and latest.status == ReconciliationStatus.CONFLICT
    # Default lease acquisition rejects CONFLICT (Invariant C)
    assert (
        state.claim_reconciliation_lease("exec_conf", "worker-contender", now=now, lease_seconds=30)
        is None
    )
    # Explicit operator re-check ALSO rejects CONFLICT (Invariant G)
    assert (
        state.claim_reconciliation_lease(
            "exec_conf",
            "operator-contender",
            now=now,
            lease_seconds=30,
            allow_terminal_recheck=True,
        )
        is None
    )


def test_non_terminal_resolutions_remain_eligible_for_default_leases(tmp_path) -> None:
    """Proves Invariants J (STILL_UNKNOWN remains eligible) and K (UNSUPPORTED remains eligible)."""
    state = SQLiteFencedReconciliationState(tmp_path / "state.sqlite")
    now = NOW + timedelta(seconds=10)

    # J: STILL_UNKNOWN remains eligible
    _insert_unknown(state.path, "exec_still_unknown")
    res_unknown = _resolve(
        state,
        _evidence(ReconciliationStatus.STILL_UNKNOWN, "e"),
        offset=2,
        execution_id="exec_still_unknown",
    )
    assert res_unknown.status == ReconciliationStatus.STILL_UNKNOWN
    lease_unknown = state.claim_reconciliation_lease(
        "exec_still_unknown", "contender", now=now, lease_seconds=30
    )
    assert lease_unknown is not None
    state.release_reconciliation_lease(lease_unknown)

    # K: UNSUPPORTED remains non-terminal and eligible
    _insert_unknown(state.path, "exec_unsupported")
    res_unsupported = _resolve(
        state,
        _evidence(ReconciliationStatus.UNSUPPORTED, "f"),
        offset=2,
        execution_id="exec_unsupported",
    )
    assert res_unsupported.status == ReconciliationStatus.UNSUPPORTED
    lease_unsupported = state.claim_reconciliation_lease(
        "exec_unsupported", "contender", now=now, lease_seconds=30
    )
    assert lease_unsupported is not None
    state.release_reconciliation_lease(lease_unsupported)
