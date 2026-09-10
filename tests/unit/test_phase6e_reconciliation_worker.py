from __future__ import annotations

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentguard.adapters.storage.sqlite import (
    ReconciliationLeaseError,
    SQLiteFencedReconciliationState,
)
from agentguard.application.reconciliation_worker import (
    ReconciliationWorker,
    ReconciliationWorkerConfig,
)
from agentguard.domain import (
    EvidenceTrustLevel,
    ExecutionAttemptIdentity,
    ExecutionRecord,
    ExternalEffectBinding,
    ExternalOperationIdentity,
    IdempotencyBinding,
    ProviderIdentity,
    ReconciliationEvidence,
    ReconciliationStatus,
)
from agentguard.ports.reconciliation_work import ReconciliationLease

NOW = datetime(2026, 9, 2, 20, 0, tzinfo=UTC)


class FixedClock:
    def __init__(self, now: datetime = NOW) -> None:
        self.value = now

    def now(self) -> datetime:
        return self.value

    def advance(self, seconds: int) -> None:
        self.value += timedelta(seconds=seconds)


def _insert_unknown(path: Path, execution_id: str = "exec_1", reserved_offset_sec: int = 2) -> None:
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
                (NOW - timedelta(seconds=reserved_offset_sec)).isoformat(),
                (NOW - timedelta(seconds=1)).isoformat(),
                NOW.isoformat(),
                "execution.outcome_ambiguous",
            ),
        )


def _binding(execution_id: str = "exec_1") -> ExternalEffectBinding:
    return ExternalEffectBinding(
        decision_id=f"decision_{execution_id}",
        intent_digest="sha256:" + "1" * 64,
        action_digest="sha256:" + "3" * 64,
        resource_digest="sha256:" + "4" * 64,
        arguments_digest="sha256:" + "5" * 64,
        provider=ProviderIdentity(
            provider_id="filesystem",
            endpoint_digest="sha256:" + "6" * 64,
        ),
        operation=ExternalOperationIdentity(
            operation_id="operation_1",
            operation_kind="mcp.tools/call",
            operation_name="read_file",
        ),
        attempt=ExecutionAttemptIdentity(
            execution_id=execution_id,
            attempt_id="attempt_1",
            attempt_number=1,
            started_at=NOW - timedelta(seconds=1),
        ),
        idempotency=IdempotencyBinding(),
    )


def _evidence() -> ReconciliationEvidence:
    return ReconciliationEvidence(
        status=ReconciliationStatus.STILL_UNKNOWN,
        source="provider-status",
        evidence_digest="sha256:" + "7" * 64,
        trust_level=EvidenceTrustLevel.PROVIDER_VERIFIED,
        observed_at=NOW + timedelta(seconds=1),
        error_code=None,
    )


def test_fenced_state_rejects_resolution_without_active_lease(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path)

    with pytest.raises(ReconciliationLeaseError, match="reconciliation.lease_required"):
        state.record_execution_resolution("exec_1", _evidence(), NOW + timedelta(seconds=1))

    assert state.list_execution_resolutions("exec_1") == ()


def test_lease_request_validation_is_fail_closed(tmp_path) -> None:
    state = SQLiteFencedReconciliationState(tmp_path / "state.sqlite")

    with pytest.raises(ReconciliationLeaseError, match="reconciliation.lease_owner_invalid"):
        state.claim_reconciliation_lease("missing", "   ", now=NOW, lease_seconds=10)
    with pytest.raises(ReconciliationLeaseError, match="reconciliation.lease_now_invalid"):
        state.claim_reconciliation_lease(
            "missing",
            "worker-a",
            now=datetime(2026, 9, 2, 20, 0),
            lease_seconds=10,
        )
    with pytest.raises(ReconciliationLeaseError, match="reconciliation.lease_ttl_invalid"):
        state.claim_reconciliation_lease("missing", "worker-a", now=NOW, lease_seconds=0)


def test_claim_rejects_missing_and_non_unknown_execution(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)

    with pytest.raises(ReconciliationLeaseError, match="execution.record_missing"):
        state.claim_reconciliation_lease("missing", "worker-a", now=NOW, lease_seconds=10)

    _insert_unknown(path)
    with sqlite3.connect(path) as connection:
        connection.execute(
            "UPDATE executions SET state = 'succeeded' WHERE execution_id = 'exec_1'"
        )
    assert state.claim_reconciliation_lease("exec_1", "worker-a", now=NOW, lease_seconds=10) is None


def test_resolution_scope_rejects_nested_and_mismatched_execution(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path, "exec_1")
    _insert_unknown(path, "exec_2")
    lease = state.claim_reconciliation_lease("exec_1", "worker-a", now=NOW, lease_seconds=30)
    assert lease is not None

    with state.resolution_lease(lease):
        with pytest.raises(ReconciliationLeaseError, match="reconciliation.lease_scope_nested"):
            with state.resolution_lease(lease):
                pass
        with pytest.raises(
            ReconciliationLeaseError,
            match="reconciliation.lease_execution_mismatch",
        ):
            state.record_execution_resolution("exec_2", _evidence(), NOW + timedelta(seconds=1))

    assert state.release_reconciliation_lease(lease) is True


def test_resolution_commit_requires_aware_reconciliation_time(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path)
    lease = state.claim_reconciliation_lease("exec_1", "worker-a", now=NOW, lease_seconds=30)
    assert lease is not None

    with state.resolution_lease(lease):
        with pytest.raises(ReconciliationLeaseError, match="reconciliation.reconciled_at_invalid"):
            state.record_execution_resolution(
                "exec_1",
                _evidence(),
                datetime(2026, 9, 2, 20, 0, 1),
            )
    assert state.release_reconciliation_lease(lease) is True


def test_reconciliation_lease_is_exclusive_and_expiry_allows_fenced_takeover(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    first = SQLiteFencedReconciliationState(path)
    second = SQLiteFencedReconciliationState(path)
    _insert_unknown(path)

    lease_a = first.claim_reconciliation_lease("exec_1", "worker-a", now=NOW, lease_seconds=10)
    assert lease_a is not None
    assert (
        second.claim_reconciliation_lease(
            "exec_1", "worker-b", now=NOW + timedelta(seconds=9), lease_seconds=10
        )
        is None
    )

    lease_b = second.claim_reconciliation_lease(
        "exec_1", "worker-b", now=NOW + timedelta(seconds=10), lease_seconds=10
    )
    assert lease_b is not None
    assert lease_b.fencing_token > lease_a.fencing_token
    assert second.get_reconciliation_lease("exec_1") == lease_b


def test_stale_worker_cannot_commit_resolution_after_lease_takeover(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    stale = SQLiteFencedReconciliationState(path)
    current = SQLiteFencedReconciliationState(path)
    _insert_unknown(path)

    lease_a = stale.claim_reconciliation_lease("exec_1", "worker-a", now=NOW, lease_seconds=5)
    assert lease_a is not None
    lease_b = current.claim_reconciliation_lease(
        "exec_1", "worker-b", now=NOW + timedelta(seconds=5), lease_seconds=30
    )
    assert lease_b is not None

    with stale.resolution_lease(lease_a):
        with pytest.raises(ReconciliationLeaseError, match="reconciliation.lease_lost"):
            stale.record_execution_resolution("exec_1", _evidence(), NOW + timedelta(seconds=6))
    assert stale.list_execution_resolutions("exec_1") == ()

    with current.resolution_lease(lease_b):
        resolution = current.record_execution_resolution(
            "exec_1", _evidence(), NOW + timedelta(seconds=6)
        )
    assert resolution.status == ReconciliationStatus.STILL_UNKNOWN
    assert current.get_reconciliation_lease("exec_1") is None


def test_lease_renewal_and_release_require_exact_live_fencing_token(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path)
    lease = state.claim_reconciliation_lease("exec_1", "worker-a", now=NOW, lease_seconds=10)
    assert lease is not None

    renewed = state.renew_reconciliation_lease(
        lease, now=NOW + timedelta(seconds=2), lease_seconds=20
    )
    assert renewed.expires_at == NOW + timedelta(seconds=22)

    forged = ReconciliationLease(
        execution_id=renewed.execution_id,
        owner_id=renewed.owner_id,
        fencing_token=renewed.fencing_token + 1,
        acquired_at=renewed.acquired_at,
        expires_at=renewed.expires_at,
    )
    assert state.release_reconciliation_lease(forged) is False
    assert state.release_reconciliation_lease(renewed) is True

    expired = state.claim_reconciliation_lease(
        "exec_1", "worker-a", now=NOW + timedelta(seconds=30), lease_seconds=1
    )
    assert expired is not None
    with pytest.raises(ReconciliationLeaseError, match="reconciliation.lease_lost"):
        state.renew_reconciliation_lease(expired, now=NOW + timedelta(seconds=31), lease_seconds=10)


class PresentProviderEffects:
    def __init__(self, binding: ExternalEffectBinding) -> None:
        self.binding = binding

    def get_external_effect_binding(self, execution_id: str) -> ExternalEffectBinding | None:
        return self.binding if execution_id == self.binding.attempt.execution_id else None


class MapProviderEffects:
    def __init__(self, bindings: dict[str, ExternalEffectBinding]) -> None:
        self.bindings = bindings

    def get_external_effect_binding(self, execution_id: str) -> ExternalEffectBinding | None:
        return self.bindings.get(execution_id)


class StaticReconciler:
    def reconcile(self, execution: ExecutionRecord) -> ReconciliationEvidence:
        assert execution.execution_id == "exec_1"
        return _evidence()


class ConfigurableReconciler:
    def __init__(self, statuses: dict[str, ReconciliationStatus] | None = None) -> None:
        self.statuses = statuses or {}
        self.reconcile_calls: list[str] = []

    def reconcile(self, execution: ExecutionRecord) -> ReconciliationEvidence:
        self.reconcile_calls.append(execution.execution_id)
        status = self.statuses.get(execution.execution_id, ReconciliationStatus.CONFIRMED_SUCCEEDED)
        return ReconciliationEvidence(
            status=status,
            source="provider-status",
            evidence_digest="sha256:" + "8" * 64,
            trust_level=EvidenceTrustLevel.PROVIDER_VERIFIED,
            observed_at=NOW + timedelta(seconds=1),
            error_code=None,
        )


class FakeService:
    def __init__(self, state: SQLiteFencedReconciliationState, clock: FixedClock) -> None:
        self.state = state
        self.clock = clock
        self.calls = 0

    def reconcile_execution(self, execution_id: str, reconciler: StaticReconciler):
        self.calls += 1
        execution = self.state.get_execution(execution_id)
        assert execution is not None
        evidence = reconciler.reconcile(execution)
        return self.state.record_execution_resolution(execution_id, evidence, self.clock.now())


class FailingService:
    def __init__(self) -> None:
        self.calls = 0

    def reconcile_execution(self, execution_id: str, reconciler: StaticReconciler):
        del execution_id, reconciler
        self.calls += 1
        raise RuntimeError("provider_reconciliation.test_failure")


class SelectiveFailingService:
    def __init__(
        self,
        state: SQLiteFencedReconciliationState,
        clock: FixedClock,
        failing_ids: set[str],
    ) -> None:
        self.state = state
        self.clock = clock
        self.failing_ids = failing_ids
        self.calls: list[str] = []

    def reconcile_execution(self, execution_id: str, reconciler: ConfigurableReconciler):
        self.calls.append(execution_id)
        if execution_id in self.failing_ids:
            raise RuntimeError(f"provider_reconciliation.failure_{execution_id}")
        execution = self.state.get_execution(execution_id)
        assert execution is not None
        evidence = reconciler.reconcile(execution)
        return self.state.record_execution_resolution(execution_id, evidence, self.clock.now())


def _worker(
    *,
    state: SQLiteFencedReconciliationState,
    clock: FixedClock,
    service,
    max_items_per_tick: int = 100,
) -> ReconciliationWorker:
    return ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=state,
        provider_effects=PresentProviderEffects(_binding()),  # type: ignore[arg-type]
        reconciler=StaticReconciler(),
        clock=clock,
        config=ReconciliationWorkerConfig(
            owner_id="worker-a",
            lease_seconds=30,
            max_items_per_tick=max_items_per_tick,
        ),
    )


def test_worker_config_validation_is_fail_closed() -> None:
    with pytest.raises(ValueError, match="reconciliation.worker_owner_invalid"):
        ReconciliationWorkerConfig(owner_id=" ")
    with pytest.raises(ValueError, match="reconciliation.worker_lease_ttl_invalid"):
        ReconciliationWorkerConfig(owner_id="worker-a", lease_seconds=0)
    with pytest.raises(ValueError, match="reconciliation.worker_max_items_invalid"):
        ReconciliationWorkerConfig(owner_id="worker-a", max_items_per_tick=0)


def test_worker_claims_only_bound_unknown_work_and_commits_under_fence(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path, "exec_1")
    _insert_unknown(path, "exec_unbound")
    clock = FixedClock(NOW + timedelta(seconds=2))
    service = FakeService(state, clock)

    worker = _worker(state=state, clock=clock, service=service)

    assert worker.probe_readiness() is True
    result = worker.run_once()
    assert result.scanned == 2
    assert result.eligible == 1
    assert result.claimed == 1
    assert result.reconciled == 1
    assert result.busy == 0
    assert result.lease_lost == 0
    assert result.failed == 0
    assert service.calls == 1
    assert state.get_reconciliation_lease("exec_1") is None
    assert len(state.list_execution_resolutions("exec_1")) == 1
    assert worker.health().ready is True

    worker.mark_stopped()
    assert worker.health().live is False
    assert worker.health().ready is False


def test_worker_readiness_failure_is_observable(tmp_path, monkeypatch) -> None:
    state = SQLiteFencedReconciliationState(tmp_path / "state.sqlite")
    clock = FixedClock()
    worker = _worker(state=state, clock=clock, service=FailingService())

    def broken_list():
        raise RuntimeError("database unavailable")

    monkeypatch.setattr(state, "list_executions", broken_list)
    assert worker.probe_readiness() is False
    health = worker.health()
    assert health.ready is False
    assert health.last_error == "RuntimeError:database unavailable"


def test_worker_item_failure_is_counted_and_releases_lease(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path)
    clock = FixedClock(NOW + timedelta(seconds=2))
    service = FailingService()
    worker = _worker(state=state, clock=clock, service=service)

    result = worker.run_once()
    assert result.claimed == 1
    assert result.reconciled == 0
    assert result.failed == 1
    assert service.calls == 1
    assert state.get_reconciliation_lease("exec_1") is None
    health = worker.health()
    assert health.ready is True
    assert health.consecutive_failed_ticks == 1
    assert health.last_error == "RuntimeError:provider_reconciliation.test_failure"


def test_worker_scan_failure_is_fatal_and_marks_not_ready(tmp_path, monkeypatch) -> None:
    state = SQLiteFencedReconciliationState(tmp_path / "state.sqlite")
    clock = FixedClock()
    worker = _worker(state=state, clock=clock, service=FailingService())

    def broken_list():
        raise RuntimeError("state offline")

    monkeypatch.setattr(state, "list_executions", broken_list)
    with pytest.raises(RuntimeError, match="state offline"):
        worker.run_once()
    health = worker.health()
    assert health.ready is False
    assert health.consecutive_failed_ticks == 1
    assert health.last_error == "RuntimeError:state offline"
    assert health.last_tick_completed_at == NOW


def test_unbound_unknown_does_not_starve_later_bound_work_at_tick_limit(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path, "exec_0_unbound")
    _insert_unknown(path, "exec_1")
    clock = FixedClock(NOW + timedelta(seconds=2))
    service = FakeService(state, clock)
    worker = _worker(state=state, clock=clock, service=service, max_items_per_tick=1)

    result = worker.run_once()
    assert result.scanned == 2
    assert result.eligible == 1
    assert result.claimed == 1
    assert result.reconciled == 1
    assert service.calls == 1
    assert len(state.list_execution_resolutions("exec_1")) == 1


def test_second_worker_observes_busy_lease_without_duplicate_reconciliation(tmp_path) -> None:
    path = tmp_path / "state.sqlite"
    holder = SQLiteFencedReconciliationState(path)
    contender = SQLiteFencedReconciliationState(path)
    _insert_unknown(path)
    clock = FixedClock(NOW + timedelta(seconds=1))
    lease = holder.claim_reconciliation_lease(
        "exec_1", "worker-holder", now=clock.now(), lease_seconds=30
    )
    assert lease is not None
    service = FakeService(contender, clock)
    worker = ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=contender,
        provider_effects=PresentProviderEffects(_binding()),  # type: ignore[arg-type]
        reconciler=StaticReconciler(),
        clock=clock,
        config=ReconciliationWorkerConfig(owner_id="worker-contender", lease_seconds=30),
    )

    result = worker.run_once()
    assert result.eligible == 1
    assert result.claimed == 0
    assert result.busy == 1
    assert result.reconciled == 0
    assert service.calls == 0


def test_repeated_worker_tick_does_not_reconcile_terminal_work(tmp_path) -> None:
    """Prove Invariant D: Repeated worker tick does not invoke provider reconciliation again after terminal resolution."""
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path, "exec_1")

    clock = FixedClock(NOW + timedelta(seconds=1))
    service = FakeService(state, clock)
    reconciler = ConfigurableReconciler({"exec_1": ReconciliationStatus.CONFIRMED_SUCCEEDED})
    worker = ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=state,
        provider_effects=MapProviderEffects({"exec_1": _binding("exec_1")}),  # type: ignore[arg-type]
        reconciler=reconciler,
        clock=clock,
        config=ReconciliationWorkerConfig(
            owner_id="worker-a", lease_seconds=30, max_items_per_tick=10
        ),
    )

    # Tick 1: Reconciles exec_1 to CONFIRMED_SUCCEEDED
    result_1 = worker.run_once()
    assert result_1.reconciled == 1
    assert service.calls == 1
    assert reconciler.reconcile_calls == ["exec_1"]
    assert len(state.list_execution_resolutions("exec_1")) == 1
    latest = state.get_latest_execution_resolution("exec_1")
    assert latest is not None and latest.status == ReconciliationStatus.CONFIRMED_SUCCEEDED

    # Tick 2: Subsequent tick skips exec_1 completely
    clock.advance(5)
    result_2 = worker.run_once()
    assert result_2.scanned == 0
    assert result_2.eligible == 0
    assert result_2.claimed == 0
    assert result_2.reconciled == 0
    # Service and reconciler were NOT called again
    assert service.calls == 1
    assert reconciler.reconcile_calls == ["exec_1"]


def test_terminal_resolved_work_does_not_starve_unresolved_work_in_bounded_tick(tmp_path) -> None:
    """Prove Invariant E: A terminal resolved exec_1 does not prevent unresolved exec_2 from being considered in bounded tick."""
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    # exec_1 is older (reserved_at = NOW - 10s)
    _insert_unknown(path, "exec_1", reserved_offset_sec=10)
    # exec_2 is newer (reserved_at = NOW - 5s)
    _insert_unknown(path, "exec_2", reserved_offset_sec=5)

    clock = FixedClock(NOW + timedelta(seconds=1))
    service = FakeService(state, clock)
    reconciler = ConfigurableReconciler(
        {
            "exec_1": ReconciliationStatus.CONFIRMED_SUCCEEDED,
            "exec_2": ReconciliationStatus.CONFIRMED_SUCCEEDED,
        }
    )
    worker = ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=state,
        provider_effects=MapProviderEffects(
            {
                "exec_1": _binding("exec_1"),
                "exec_2": _binding("exec_2"),
            }
        ),  # type: ignore[arg-type]
        reconciler=reconciler,
        clock=clock,
        config=ReconciliationWorkerConfig(
            owner_id="worker-a", lease_seconds=30, max_items_per_tick=1
        ),
    )

    # Tick 1: Reconciles exec_1 within bounded capacity (max_items_per_tick=1)
    result_1 = worker.run_once()
    assert result_1.reconciled == 1
    assert service.calls == 1
    assert reconciler.reconcile_calls == ["exec_1"]
    assert len(state.list_execution_resolutions("exec_1")) == 1
    assert len(state.list_execution_resolutions("exec_2")) == 0

    # Tick 2: exec_1 is terminal and skipped, allowing exec_2 to be processed within bounded capacity
    clock.advance(5)
    result_2 = worker.run_once()
    assert result_2.reconciled == 1
    assert service.calls == 2
    assert reconciler.reconcile_calls == ["exec_1", "exec_2"]
    assert len(state.list_execution_resolutions("exec_2")) == 1
    latest_2 = state.get_latest_execution_resolution("exec_2")
    assert latest_2 is not None and latest_2.status == ReconciliationStatus.CONFIRMED_SUCCEEDED


def test_still_unknown_work_remains_eligible_on_subsequent_ticks(tmp_path) -> None:
    """Prove Invariant F: STILL_UNKNOWN remains eligible for future reconciliation."""
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path, "exec_1")

    clock = FixedClock(NOW + timedelta(seconds=1))
    service = FakeService(state, clock)
    reconciler = ConfigurableReconciler({"exec_1": ReconciliationStatus.STILL_UNKNOWN})
    worker = ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=state,
        provider_effects=MapProviderEffects({"exec_1": _binding("exec_1")}),  # type: ignore[arg-type]
        reconciler=reconciler,
        clock=clock,
        config=ReconciliationWorkerConfig(
            owner_id="worker-a", lease_seconds=30, max_items_per_tick=10
        ),
    )

    # Tick 1: Reconciles exec_1 to STILL_UNKNOWN
    result_1 = worker.run_once()
    assert result_1.reconciled == 1
    assert service.calls == 1
    assert reconciler.reconcile_calls == ["exec_1"]
    latest = state.get_latest_execution_resolution("exec_1")
    assert latest is not None and latest.status == ReconciliationStatus.STILL_UNKNOWN

    # Tick 2: Because STILL_UNKNOWN is non-terminal, exec_1 remains eligible
    clock.advance(5)
    result_2 = worker.run_once()
    assert result_2.eligible == 1
    assert result_2.claimed == 1
    assert result_2.reconciled == 1
    assert service.calls == 2
    assert reconciler.reconcile_calls == ["exec_1", "exec_1"]


def test_unsupported_work_remains_eligible_on_subsequent_ticks(tmp_path) -> None:
    """Prove Invariant G: Characterize and preserve existing UNSUPPORTED behavior as non-terminal."""
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path, "exec_1")

    clock = FixedClock(NOW + timedelta(seconds=1))
    service = FakeService(state, clock)
    reconciler = ConfigurableReconciler({"exec_1": ReconciliationStatus.UNSUPPORTED})
    worker = ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=state,
        provider_effects=MapProviderEffects({"exec_1": _binding("exec_1")}),  # type: ignore[arg-type]
        reconciler=reconciler,
        clock=clock,
        config=ReconciliationWorkerConfig(
            owner_id="worker-a", lease_seconds=30, max_items_per_tick=10
        ),
    )

    # Tick 1: Reconciles exec_1 to UNSUPPORTED
    result_1 = worker.run_once()
    assert result_1.reconciled == 1
    assert service.calls == 1
    assert reconciler.reconcile_calls == ["exec_1"]
    latest = state.get_latest_execution_resolution("exec_1")
    assert latest is not None and latest.status == ReconciliationStatus.UNSUPPORTED

    # Tick 2: Because UNSUPPORTED is non-terminal, exec_1 remains eligible
    clock.advance(5)
    result_2 = worker.run_once()
    assert result_2.eligible == 1
    assert result_2.claimed == 1
    assert result_2.reconciled == 1
    assert service.calls == 2
    assert reconciler.reconcile_calls == ["exec_1", "exec_1"]


def test_busy_lease_does_not_consume_tick_quota(tmp_path) -> None:
    """Prove Invariant A: Active lease contention does not consume provider-attempt quota in the same tick."""
    path = tmp_path / "state.sqlite"
    holder = SQLiteFencedReconciliationState(path)
    state = SQLiteFencedReconciliationState(path)
    # exec_1 is older (offset 10), exec_2 is newer (offset 5)
    _insert_unknown(path, "exec_1", reserved_offset_sec=10)
    _insert_unknown(path, "exec_2", reserved_offset_sec=5)

    clock = FixedClock(NOW + timedelta(seconds=1))
    # Pre-claim lease on exec_1 with external holder
    lease_1 = holder.claim_reconciliation_lease(
        "exec_1", "external-holder", now=clock.now(), lease_seconds=30
    )
    assert lease_1 is not None

    service = FakeService(state, clock)
    reconciler = ConfigurableReconciler(
        {
            "exec_1": ReconciliationStatus.CONFIRMED_SUCCEEDED,
            "exec_2": ReconciliationStatus.CONFIRMED_SUCCEEDED,
        }
    )
    worker = ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=state,
        provider_effects=MapProviderEffects(
            {
                "exec_1": _binding("exec_1"),
                "exec_2": _binding("exec_2"),
            }
        ),  # type: ignore[arg-type]
        reconciler=reconciler,
        clock=clock,
        config=ReconciliationWorkerConfig(
            owner_id="worker-b", lease_seconds=30, max_items_per_tick=1
        ),
    )

    # Same tick encounters busy exec_1, does not consume quota, and proceeds to claim & reconcile exec_2
    result = worker.run_once()
    assert result.scanned == 2
    assert result.eligible == 2
    assert result.busy == 1
    assert result.claimed == 1
    assert result.reconciled == 1
    assert service.calls == 1
    assert reconciler.reconcile_calls == ["exec_2"]
    assert worker.cursor_id == "exec_2"


def test_provider_failure_round_robin_progress(tmp_path) -> None:
    """Prove Invariant B: Failing execution yields to subsequent actionable execution on next tick."""
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path, "exec_1", reserved_offset_sec=10)
    _insert_unknown(path, "exec_2", reserved_offset_sec=5)

    clock = FixedClock(NOW + timedelta(seconds=1))
    service = SelectiveFailingService(state, clock, failing_ids={"exec_1"})
    reconciler = ConfigurableReconciler(
        {
            "exec_1": ReconciliationStatus.CONFIRMED_SUCCEEDED,
            "exec_2": ReconciliationStatus.CONFIRMED_SUCCEEDED,
        }
    )
    worker = ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=state,
        provider_effects=MapProviderEffects(
            {
                "exec_1": _binding("exec_1"),
                "exec_2": _binding("exec_2"),
            }
        ),  # type: ignore[arg-type]
        reconciler=reconciler,
        clock=clock,
        config=ReconciliationWorkerConfig(
            owner_id="worker-a", lease_seconds=30, max_items_per_tick=1
        ),
    )

    # Tick 1: exec_1 is claimed, provider fails
    result_1 = worker.run_once()
    assert result_1.claimed == 1
    assert result_1.failed == 1
    assert result_1.reconciled == 0
    assert service.calls == ["exec_1"]
    assert worker.cursor_id == "exec_1"

    # Tick 2: Traversal rotates and exec_2 receives attempt instead of retrying exec_1
    clock.advance(5)
    result_2 = worker.run_once()
    assert result_2.claimed == 1
    assert result_2.reconciled == 1
    assert result_2.failed == 0
    assert service.calls == ["exec_1", "exec_2"]
    assert worker.cursor_id == "exec_2"


def test_still_unknown_round_robin_progress(tmp_path) -> None:
    """Prove Invariant C: Non-progressing STILL_UNKNOWN execution yields opportunity to next execution."""
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path, "exec_1", reserved_offset_sec=10)
    _insert_unknown(path, "exec_2", reserved_offset_sec=5)

    clock = FixedClock(NOW + timedelta(seconds=1))
    service = FakeService(state, clock)
    reconciler = ConfigurableReconciler(
        {
            "exec_1": ReconciliationStatus.STILL_UNKNOWN,
            "exec_2": ReconciliationStatus.CONFIRMED_SUCCEEDED,
        }
    )
    worker = ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=state,
        provider_effects=MapProviderEffects(
            {
                "exec_1": _binding("exec_1"),
                "exec_2": _binding("exec_2"),
            }
        ),  # type: ignore[arg-type]
        reconciler=reconciler,
        clock=clock,
        config=ReconciliationWorkerConfig(
            owner_id="worker-a", lease_seconds=30, max_items_per_tick=1
        ),
    )

    # Tick 1: Reconciles exec_1 -> STILL_UNKNOWN
    result_1 = worker.run_once()
    assert result_1.claimed == 1
    assert result_1.reconciled == 1
    assert reconciler.reconcile_calls == ["exec_1"]
    assert worker.cursor_id == "exec_1"

    # Tick 2: Traversal rotates; exec_2 gets opportunity
    clock.advance(5)
    result_2 = worker.run_once()
    assert result_2.claimed == 1
    assert result_2.reconciled == 1
    assert reconciler.reconcile_calls == ["exec_1", "exec_2"]
    assert worker.cursor_id == "exec_2"


def test_unsupported_round_robin_progress(tmp_path) -> None:
    """Prove Invariant D: Non-terminal UNSUPPORTED execution yields opportunity to next execution."""
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path, "exec_1", reserved_offset_sec=10)
    _insert_unknown(path, "exec_2", reserved_offset_sec=5)

    clock = FixedClock(NOW + timedelta(seconds=1))
    service = FakeService(state, clock)
    reconciler = ConfigurableReconciler(
        {
            "exec_1": ReconciliationStatus.UNSUPPORTED,
            "exec_2": ReconciliationStatus.CONFIRMED_SUCCEEDED,
        }
    )
    worker = ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=state,
        provider_effects=MapProviderEffects(
            {
                "exec_1": _binding("exec_1"),
                "exec_2": _binding("exec_2"),
            }
        ),  # type: ignore[arg-type]
        reconciler=reconciler,
        clock=clock,
        config=ReconciliationWorkerConfig(
            owner_id="worker-a", lease_seconds=30, max_items_per_tick=1
        ),
    )

    # Tick 1: Reconciles exec_1 -> UNSUPPORTED
    result_1 = worker.run_once()
    assert result_1.claimed == 1
    assert result_1.reconciled == 1
    assert reconciler.reconcile_calls == ["exec_1"]
    assert worker.cursor_id == "exec_1"
    latest_1 = state.get_latest_execution_resolution("exec_1")
    assert latest_1 is not None and latest_1.status == ReconciliationStatus.UNSUPPORTED

    # Tick 2: Traversal rotates; exec_2 gets opportunity
    clock.advance(5)
    result_2 = worker.run_once()
    assert result_2.claimed == 1
    assert result_2.reconciled == 1
    assert reconciler.reconcile_calls == ["exec_1", "exec_2"]
    assert worker.cursor_id == "exec_2"


def test_round_robin_cursor_wraps_around(tmp_path) -> None:
    """Prove Invariant E: Traversal wraps cleanly back to first candidate after reaching end of snapshot."""
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path, "exec_1", reserved_offset_sec=15)
    _insert_unknown(path, "exec_2", reserved_offset_sec=10)
    _insert_unknown(path, "exec_3", reserved_offset_sec=5)

    clock = FixedClock(NOW + timedelta(seconds=1))
    service = FakeService(state, clock)
    reconciler = ConfigurableReconciler(
        {
            "exec_1": ReconciliationStatus.STILL_UNKNOWN,
            "exec_2": ReconciliationStatus.STILL_UNKNOWN,
            "exec_3": ReconciliationStatus.STILL_UNKNOWN,
        }
    )
    worker = ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=state,
        provider_effects=MapProviderEffects(
            {
                "exec_1": _binding("exec_1"),
                "exec_2": _binding("exec_2"),
                "exec_3": _binding("exec_3"),
            }
        ),  # type: ignore[arg-type]
        reconciler=reconciler,
        clock=clock,
        config=ReconciliationWorkerConfig(
            owner_id="worker-a", lease_seconds=30, max_items_per_tick=1
        ),
    )

    # Tick 1 -> exec_1
    worker.run_once()
    assert worker.cursor_id == "exec_1"

    # Tick 2 -> exec_2
    clock.advance(5)
    worker.run_once()
    assert worker.cursor_id == "exec_2"

    # Tick 3 -> exec_3 (end of candidate list)
    clock.advance(5)
    worker.run_once()
    assert worker.cursor_id == "exec_3"

    # Tick 4 -> wraps around to exec_1
    clock.advance(5)
    worker.run_once()
    assert worker.cursor_id == "exec_1"
    assert reconciler.reconcile_calls == ["exec_1", "exec_2", "exec_3", "exec_1"]


def test_all_busy_candidates_tick_terminates_cleanly(tmp_path) -> None:
    """Prove Invariant F: When all candidates are busy, tick terminates without infinite loop."""
    path = tmp_path / "state.sqlite"
    holder = SQLiteFencedReconciliationState(path)
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path, "exec_1", reserved_offset_sec=15)
    _insert_unknown(path, "exec_2", reserved_offset_sec=10)
    _insert_unknown(path, "exec_3", reserved_offset_sec=5)

    clock = FixedClock(NOW + timedelta(seconds=1))
    for exec_id in ("exec_1", "exec_2", "exec_3"):
        lease = holder.claim_reconciliation_lease(
            exec_id, "external-holder", now=clock.now(), lease_seconds=30
        )
        assert lease is not None

    service = FakeService(state, clock)
    reconciler = ConfigurableReconciler()
    worker = ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=state,
        provider_effects=MapProviderEffects(
            {
                "exec_1": _binding("exec_1"),
                "exec_2": _binding("exec_2"),
                "exec_3": _binding("exec_3"),
            }
        ),  # type: ignore[arg-type]
        reconciler=reconciler,
        clock=clock,
        config=ReconciliationWorkerConfig(
            owner_id="worker-a", lease_seconds=30, max_items_per_tick=2
        ),
    )

    result = worker.run_once()
    assert result.scanned == 3
    assert result.eligible == 3
    assert result.busy == 3
    assert result.claimed == 0
    assert result.reconciled == 0
    assert service.calls == 0
    assert worker.cursor_id is None


def test_terminal_resolutions_remain_excluded(tmp_path) -> None:
    """Prove Invariant G: CONFIRMED_SUCCEEDED, CONFIRMED_FAILED, and CONFLICT remain excluded from scheduling."""
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    clock = FixedClock(NOW + timedelta(seconds=1))

    # 1. exec_succ (CONFIRMED_SUCCEEDED)
    _insert_unknown(path, "exec_succ", reserved_offset_sec=20)
    lease_s = state.claim_reconciliation_lease(
        "exec_succ", "setup", now=clock.now(), lease_seconds=10
    )
    assert lease_s is not None
    with state.resolution_lease(lease_s):
        state.record_execution_resolution(
            "exec_succ",
            ReconciliationEvidence(
                status=ReconciliationStatus.CONFIRMED_SUCCEEDED,
                source="provider",
                evidence_digest="sha256:" + "1" * 64,
                trust_level=EvidenceTrustLevel.PROVIDER_VERIFIED,
                observed_at=clock.now(),
            ),
            clock.now(),
        )

    # 2. exec_fail (CONFIRMED_FAILED)
    _insert_unknown(path, "exec_fail", reserved_offset_sec=15)
    lease_f = state.claim_reconciliation_lease(
        "exec_fail", "setup", now=clock.now(), lease_seconds=10
    )
    assert lease_f is not None
    with state.resolution_lease(lease_f):
        state.record_execution_resolution(
            "exec_fail",
            ReconciliationEvidence(
                status=ReconciliationStatus.CONFIRMED_FAILED,
                source="provider",
                evidence_digest="sha256:" + "2" * 64,
                trust_level=EvidenceTrustLevel.PROVIDER_VERIFIED,
                observed_at=clock.now(),
            ),
            clock.now(),
        )

    # 3. exec_conf (CONFLICT)
    _insert_unknown(path, "exec_conf", reserved_offset_sec=10)
    lease_c1 = state.claim_reconciliation_lease(
        "exec_conf", "setup", now=clock.now(), lease_seconds=10
    )
    assert lease_c1 is not None
    with state.resolution_lease(lease_c1):
        state.record_execution_resolution(
            "exec_conf",
            ReconciliationEvidence(
                status=ReconciliationStatus.CONFIRMED_SUCCEEDED,
                source="provider",
                evidence_digest="sha256:" + "3" * 64,
                trust_level=EvidenceTrustLevel.PROVIDER_VERIFIED,
                observed_at=clock.now(),
            ),
            clock.now(),
        )
    clock.advance(1)
    lease_c2 = state.claim_reconciliation_lease(
        "exec_conf", "setup", now=clock.now(), lease_seconds=10, allow_terminal_recheck=True
    )
    assert lease_c2 is not None
    with state.resolution_lease(lease_c2):
        state.record_execution_resolution(
            "exec_conf",
            ReconciliationEvidence(
                status=ReconciliationStatus.CONFIRMED_FAILED,
                source="provider",
                evidence_digest="sha256:" + "4" * 64,
                trust_level=EvidenceTrustLevel.PROVIDER_VERIFIED,
                observed_at=clock.now(),
            ),
            clock.now(),
        )
    latest_c = state.get_latest_execution_resolution("exec_conf")
    assert latest_c is not None and latest_c.status == ReconciliationStatus.CONFLICT

    # 4. exec_pending (actionable UNKNOWN)
    _insert_unknown(path, "exec_pending", reserved_offset_sec=5)

    service = FakeService(state, clock)
    reconciler = ConfigurableReconciler({"exec_pending": ReconciliationStatus.CONFIRMED_SUCCEEDED})
    worker = ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=state,
        provider_effects=MapProviderEffects(
            {
                "exec_succ": _binding("exec_succ"),
                "exec_fail": _binding("exec_fail"),
                "exec_conf": _binding("exec_conf"),
                "exec_pending": _binding("exec_pending"),
            }
        ),  # type: ignore[arg-type]
        reconciler=reconciler,
        clock=clock,
        config=ReconciliationWorkerConfig(
            owner_id="worker-a", lease_seconds=30, max_items_per_tick=10
        ),
    )

    result = worker.run_once()
    assert result.scanned == 1
    assert result.eligible == 1
    assert result.claimed == 1
    assert result.reconciled == 1
    assert reconciler.reconcile_calls == ["exec_pending"]
    assert worker.cursor_id == "exec_pending"


def test_cursor_advances_on_claim_even_when_provider_fails(tmp_path) -> None:
    """Prove Invariant H: Cursor advances on successful lease claim before provider reconciliation executes."""
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path, "exec_1", reserved_offset_sec=10)
    _insert_unknown(path, "exec_2", reserved_offset_sec=5)

    clock = FixedClock(NOW + timedelta(seconds=1))
    service = SelectiveFailingService(state, clock, failing_ids={"exec_1"})
    reconciler = ConfigurableReconciler({"exec_2": ReconciliationStatus.CONFIRMED_SUCCEEDED})
    worker = ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=state,
        provider_effects=MapProviderEffects(
            {
                "exec_1": _binding("exec_1"),
                "exec_2": _binding("exec_2"),
            }
        ),  # type: ignore[arg-type]
        reconciler=reconciler,
        clock=clock,
        config=ReconciliationWorkerConfig(
            owner_id="worker-a", lease_seconds=30, max_items_per_tick=1
        ),
    )

    assert worker.cursor_id is None
    result = worker.run_once()
    assert result.claimed == 1
    assert result.failed == 1
    assert worker.cursor_id == "exec_1"


def test_missing_cursor_falls_back_to_canonical_order(tmp_path) -> None:
    """Prove Invariant I: If cursor execution is not found in snapshot, safely fall back to canonical storage order."""
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    _insert_unknown(path, "exec_1", reserved_offset_sec=10)
    _insert_unknown(path, "exec_2", reserved_offset_sec=5)

    clock = FixedClock(NOW + timedelta(seconds=1))
    service = FakeService(state, clock)
    reconciler = ConfigurableReconciler(
        {
            "exec_1": ReconciliationStatus.CONFIRMED_SUCCEEDED,
            "exec_2": ReconciliationStatus.CONFIRMED_SUCCEEDED,
        }
    )
    worker = ReconciliationWorker(
        service=service,  # type: ignore[arg-type]
        state=state,
        provider_effects=MapProviderEffects(
            {
                "exec_1": _binding("exec_1"),
                "exec_2": _binding("exec_2"),
            }
        ),  # type: ignore[arg-type]
        reconciler=reconciler,
        clock=clock,
        config=ReconciliationWorkerConfig(
            owner_id="worker-a", lease_seconds=30, max_items_per_tick=1
        ),
    )

    worker._cursor_id = "non_existent_execution_id"

    result = worker.run_once()
    assert result.claimed == 1
    assert result.reconciled == 1
    assert reconciler.reconcile_calls == ["exec_1"]
    assert worker.cursor_id == "exec_1"


def test_empty_execution_list_terminates_cleanly(tmp_path) -> None:
    """Prove clean termination when executions snapshot is empty."""
    path = tmp_path / "state.sqlite"
    state = SQLiteFencedReconciliationState(path)
    clock = FixedClock(NOW)
    service = FakeService(state, clock)
    worker = _worker(state=state, clock=clock, service=service)

    result = worker.run_once()
    assert result.scanned == 0
    assert result.eligible == 0
    assert result.claimed == 0
    assert result.reconciled == 0
    assert result.busy == 0
    assert worker.cursor_id is None
