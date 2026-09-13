from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Barrier, BrokenBarrierError
from typing import Callable, TypeAlias, cast
from uuid import uuid4

from agentguard.adapters.storage.sqlite import ReconciliationLeaseError
from agentguard.domain import (
    EvidenceTrustLevel,
    ExecutionStatus,
    ReconciliationEvidence,
    ReconciliationStatus,
)
from agentguard.engine.canonical import digest
from agentguard.engine.execution import validate_execution_authority

from .arms import (
    A0Arm,
    A1Arm,
    AgentGuardTicket,
    AuthorityHandle,
    B4Arm,
    B4Ticket,
    DispatchBehavior,
    DispatchRecord,
    _ResearchProviderExecutor,
)
from .fence import ConventionalReconciliationFence
from .models import Arm, ProviderEvidence, ProviderStratum, Schedule, TrialObservation, TrialSpec
from .provider import IndependentEffectOracleProcess, OracleIsolationError, SimulatedProvider
from .trace import HarnessInvalidReason, TrialTraceRecorder, invalid_observation, validate_trace

ResearchArm: TypeAlias = A0Arm | A1Arm | B4Arm
ResearchTicket: TypeAlias = AgentGuardTicket | B4Ticket
AuthorityToken: TypeAlias = AuthorityHandle | str


class HarnessProtocolError(RuntimeError):
    pass


class HarnessScheduleError(HarnessProtocolError):
    pass


class DevTrialHarness:
    """DEV-only executor for the exact S0-S11 preregistered schedules."""

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _arm(self, spec: TrialSpec, trial_root: Path) -> ResearchArm:
        if spec.arm == Arm.A0:
            return A0Arm(trial_root / "a0")
        if spec.arm == Arm.A1:
            return A1Arm(trial_root / "a1")
        return B4Arm(trial_root / "b4")

    @staticmethod
    def _idem(spec: TrialSpec) -> str | None:
        return spec.effect_key if spec.provider == ProviderStratum.P1 else None

    @staticmethod
    def _new_ticket(arm: ResearchArm, spec: TrialSpec) -> tuple[AuthorityToken, ResearchTicket]:
        authority = arm.acquire_authority(spec.alpha, spec.effect_key)
        if isinstance(arm, B4Arm):
            return authority, arm.issue_ticket(spec.alpha, spec.effect_key)
        handle = cast(AuthorityHandle, authority)
        return handle, arm.issue_ticket(handle, spec.trial_id)

    @staticmethod
    def _dispatch(
        arm: ResearchArm,
        ticket: ResearchTicket,
        *,
        spec: TrialSpec,
        provider: SimulatedProvider,
        behavior: DispatchBehavior,
        parent_attempt_id: str | None = None,
        allow_same_slot_retry: bool = False,
    ) -> DispatchRecord:
        if isinstance(arm, B4Arm):
            return arm.dispatch(
                cast(B4Ticket, ticket),
                trial_id=spec.trial_id,
                provider_simulator=provider,
                provider=spec.provider,
                idempotency_key=DevTrialHarness._idem(spec),
                behavior=behavior,
                parent_attempt_id=parent_attempt_id,
                allow_same_slot_retry=allow_same_slot_retry,
            )
        return arm.dispatch(
            cast(AgentGuardTicket, ticket),
            trial_id=spec.trial_id,
            provider_simulator=provider,
            provider=spec.provider,
            idempotency_key=DevTrialHarness._idem(spec),
            behavior=behavior,
        )

    @staticmethod
    def _try(call: Callable[[], object]) -> bool:
        try:
            call()
            return True
        except Exception:
            return False

    @staticmethod
    def _lineage_parent(record: DispatchRecord) -> str:
        return record.lineage_attempt_id or record.attempt_id

    def _safe_successor(
        self,
        arm: ResearchArm,
        spec: TrialSpec,
        provider: SimulatedProvider,
        predecessor: DispatchRecord,
        *,
        evidence: ProviderEvidence | None = None,
    ) -> bool:
        if isinstance(arm, A1Arm):
            return self._try(
                lambda: arm.dispatch_successor(
                    alpha=spec.alpha,
                    effect_key=spec.effect_key,
                    predecessor_lineage_attempt_id=self._lineage_parent(predecessor),
                    evidence=evidence,
                    trial_id=spec.trial_id,
                    provider_simulator=provider,
                    provider=spec.provider,
                    idempotency_key=self._idem(spec),
                    behavior="normal",
                )
            )
        if isinstance(arm, B4Arm):
            return self._try(
                lambda: arm.dispatch_successor(
                    alpha=spec.alpha,
                    effect_key=spec.effect_key,
                    predecessor_attempt_id=predecessor.attempt_id,
                    evidence=evidence,
                    trial_id=spec.trial_id,
                    provider_simulator=provider,
                    provider=spec.provider,
                    idempotency_key=self._idem(spec),
                    behavior="normal",
                )
            )
        _, replacement = self._new_ticket(arm, spec)
        return self._try(
            lambda: self._dispatch(
                arm, replacement, spec=spec, provider=provider, behavior="normal"
            )
        )

    @staticmethod
    def _await_barrier(barrier: Barrier, trace: TrialTraceRecorder, participant: str) -> None:
        trace.event("barrier.ready", participant=participant)
        try:
            barrier.wait(timeout=5.0)
        except BrokenBarrierError as exc:
            trace.event("barrier.failed", participant=participant)
            raise HarnessScheduleError("required schedule barrier failed") from exc
        trace.event("barrier.released", participant=participant)

    @staticmethod
    def _close_oracle(oracle_process: IndependentEffectOracleProcess) -> str | None:
        try:
            oracle_process.close()
        except OracleIsolationError as exc:
            return str(exc)
        return None

    def run(self, spec: TrialSpec) -> TrialObservation:
        trial_root = self.root / spec.trial_id
        if trial_root.exists() and any(trial_root.iterdir()):
            return invalid_observation(spec, HarnessInvalidReason.DIRTY_NAMESPACE)
        trial_root.mkdir(parents=True, exist_ok=True)
        trace_path = trial_root / "trace.jsonl"
        try:
            trace = TrialTraceRecorder(trace_path, spec)
        except OSError as exc:
            return invalid_observation(
                spec, HarnessInvalidReason.TRACE_CORRUPT, detail=type(exc).__name__
            )

        try:
            oracle_process = IndependentEffectOracleProcess(trial_root / "oracle.sqlite")
        except Exception as exc:
            trace.event("harness.invalid", reason=HarnessInvalidReason.ORACLE_UNAVAILABLE.value)
            trace.close()
            return invalid_observation(
                spec, HarnessInvalidReason.ORACLE_UNAVAILABLE, detail=type(exc).__name__
            )

        provider = SimulatedProvider(trial_root / "provider.sqlite", oracle_process.sink)
        arm = self._arm(spec, trial_root)
        arm.register_alpha(spec.alpha, spec.effect_key)
        started = time.monotonic()
        unsafe_successor = False
        stale_commit_accepted = False
        operator_interventions = 0
        reconciliation_calls = 0
        unresolved = False
        harness_invalid_reason: str | None = None
        trace.event("schedule.enter", schedule=spec.schedule.value)

        try:
            if spec.schedule == Schedule.S0:
                _, ticket = self._new_ticket(arm, spec)
                result = self._dispatch(
                    arm, ticket, spec=spec, provider=provider, behavior="normal"
                )
                unresolved = result.status == ExecutionStatus.UNKNOWN

            elif spec.schedule == Schedule.S1:
                _, ticket = self._new_ticket(arm, spec)
                self._dispatch(arm, ticket, spec=spec, provider=provider, behavior="normal")
                self._try(
                    lambda: self._dispatch(
                        arm, ticket, spec=spec, provider=provider, behavior="normal"
                    )
                )

            elif spec.schedule == Schedule.S2:
                authority, ticket = self._new_ticket(arm, spec)
                self._dispatch(arm, ticket, spec=spec, provider=provider, behavior="normal")
                if isinstance(arm, B4Arm):
                    fresh = arm.issue_ticket(spec.alpha, spec.effect_key)
                    self._try(
                        lambda: self._dispatch(
                            arm, fresh, spec=spec, provider=provider, behavior="normal"
                        )
                    )
                else:
                    self._try(
                        lambda: arm.issue_ticket(cast(AuthorityHandle, authority), spec.trial_id)
                    )

            elif spec.schedule == Schedule.S3:
                _, first = self._new_ticket(arm, spec)
                self._dispatch(arm, first, spec=spec, provider=provider, behavior="normal")
                try:
                    _, second = self._new_ticket(arm, spec)
                    self._dispatch(arm, second, spec=spec, provider=provider, behavior="normal")
                except Exception as exc:
                    trace.event(
                        "sut.rejection", phase="fresh-root-pressure", error=type(exc).__name__
                    )

            elif spec.schedule == Schedule.S4:
                barrier = Barrier(2)

                def acquire_and_dispatch(worker: int) -> bool:
                    self._await_barrier(barrier, trace, f"duplicate-{worker}")
                    try:
                        _, ticket = self._new_ticket(arm, spec)
                        admitted = self._try(
                            lambda: self._dispatch(
                                arm, ticket, spec=spec, provider=provider, behavior="normal"
                            )
                        )
                        trace.event("s4.worker.result", worker=worker, admitted=admitted)
                        return admitted
                    except Exception as exc:
                        trace.event(
                            "s4.worker.result",
                            worker=worker,
                            admitted=False,
                            error=type(exc).__name__,
                        )
                        return False

                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(acquire_and_dispatch, worker) for worker in range(2)]
                    for future in futures:
                        future.result()

            elif spec.schedule == Schedule.S5:
                authority, _ = self._new_ticket(arm, spec)
                if isinstance(arm, B4Arm):
                    self._try(lambda: arm.acquire_authority(spec.alpha, spec.effect_key))
                else:
                    handle = cast(AuthorityHandle, authority)
                    self._try(
                        lambda: arm.service.issue_capability_lease(
                            handle.root_grant_id,
                            arm._intent_template.principal,
                            maximum_uses=1,
                        )
                    )

            elif spec.schedule == Schedule.S6:
                _, ticket = self._new_ticket(arm, spec)
                operator_interventions += 1
                if isinstance(arm, B4Arm):
                    b4_ticket = cast(B4Ticket, ticket)
                    attempt_id = arm.lineage.begin_attempt(spec.alpha, spec.provider)
                    trace.event("s6.reserved", attempt_id=attempt_id, arm="B4")
                    try:
                        _, replacement = self._new_ticket(arm, spec)
                        self._try(
                            lambda: self._dispatch(
                                arm,
                                replacement,
                                spec=spec,
                                provider=provider,
                                behavior="normal",
                            )
                        )
                    except Exception as exc:
                        trace.event(
                            "sut.rejection", phase="s6-replacement", error=type(exc).__name__
                        )
                    arm.lineage.mark_dispatching(spec.alpha, attempt_id)
                    provider.accept(
                        trial_id=spec.trial_id,
                        provider=spec.provider,
                        attempt_id=attempt_id,
                        effect_key=b4_ticket.effect_key,
                        idempotency_key=self._idem(spec),
                    )
                    provider.commit(attempt_id)
                    arm.lineage.mark_effect(spec.alpha, attempt_id)
                else:
                    agentguard_ticket = cast(AgentGuardTicket, ticket)
                    execution_id = "exec_research_reserved_" + uuid4().hex
                    arm.service._validate_intent_authority(agentguard_ticket.intent)
                    verified = validate_execution_authority(
                        agentguard_ticket.intent,
                        agentguard_ticket.receipt,
                        agentguard_ticket.credential,
                        arm.verifier,
                        execution_id=execution_id,
                        broker_grant_verifier=arm.broker.verifier,
                        current_policy=arm.policy,
                        execution_repository=arm.state,
                    )
                    error = arm.state.reserve_execution(verified, datetime.now(UTC))
                    if error is not None:
                        raise RuntimeError(error)
                    trace.event("s6.reserved", attempt_id=execution_id, arm=spec.arm.value)
                    lineage_attempt_id: str | None = None
                    if isinstance(arm, A1Arm):
                        arm.lineage.reserve_slot(spec.alpha)
                        lineage_attempt_id = arm.lineage.begin_attempt(spec.alpha, spec.provider)
                    try:
                        _, replacement = self._new_ticket(arm, spec)
                        self._try(
                            lambda: self._dispatch(
                                arm,
                                replacement,
                                spec=spec,
                                provider=provider,
                                behavior="normal",
                            )
                        )
                    except Exception as exc:
                        trace.event(
                            "sut.rejection", phase="s6-replacement", error=type(exc).__name__
                        )
                    protected_executor = _ResearchProviderExecutor(
                        provider_simulator=provider,
                        trial_id=spec.trial_id,
                        provider=spec.provider,
                        effect_key=spec.effect_key,
                        idempotency_key=self._idem(spec),
                        behavior="normal",
                    )
                    if isinstance(arm, A1Arm) and lineage_attempt_id is not None:
                        arm.lineage.mark_dispatching(spec.alpha, lineage_attempt_id)
                    outcome = arm.service.resume_reserved_execution(
                        execution_id,
                        agentguard_ticket.intent,
                        agentguard_ticket.receipt,
                        agentguard_ticket.credential,
                        protected_executor,
                        current_policy=arm.policy,
                    )
                    if isinstance(arm, A1Arm) and lineage_attempt_id is not None:
                        if outcome.status == ExecutionStatus.SUCCESS:
                            arm.lineage.mark_effect(spec.alpha, lineage_attempt_id)
                        else:
                            arm.lineage.mark_unknown(spec.alpha, lineage_attempt_id)

            elif spec.schedule in {Schedule.S7, Schedule.S8, Schedule.S10}:
                _, first = self._new_ticket(arm, spec)
                behavior: DispatchBehavior = (
                    "commit_response_lost" if spec.schedule == Schedule.S8 else "unknown_no_effect"
                )
                first_result = self._dispatch(
                    arm, first, spec=spec, provider=provider, behavior=behavior
                )
                unresolved = first_result.status == ExecutionStatus.UNKNOWN
                roots_before = arm.root_allocations if isinstance(arm, A0Arm) else 1
                admitted = self._safe_successor(arm, spec, provider, first_result)
                trace.event(
                    "successor.pressure", admitted=admitted, predecessor=first_result.attempt_id
                )
                if admitted:
                    unresolved = False
                    if spec.provider != ProviderStratum.P1:
                        if isinstance(arm, A0Arm) and not isinstance(arm, A1Arm):
                            unsafe_successor = arm.root_allocations > roots_before
                        else:
                            unsafe_successor = True
                if spec.schedule == Schedule.S10:
                    provider.commit(first_result.attempt_id)

            elif spec.schedule == Schedule.S9:
                _, first = self._new_ticket(arm, spec)
                first_result = self._dispatch(
                    arm, first, spec=spec, provider=provider, behavior="delayed"
                )
                unresolved = True
                reconciliation_calls += 1
                evidence = provider.status(first_result.attempt_id)
                if spec.provider == ProviderStratum.P3:
                    evidence = provider.certify_no_effect_and_fence(first_result.attempt_id)
                trace.event(
                    "reconciliation.evidence",
                    status=evidence.status,
                    authoritative=evidence.authoritative,
                    no_effect_certified=evidence.no_effect_certified,
                    predecessor_fenced=evidence.predecessor_fenced,
                )
                roots_before = arm.root_allocations if isinstance(arm, A0Arm) else 1
                admitted = False
                if spec.provider in {ProviderStratum.P1, ProviderStratum.P3}:
                    admitted = self._safe_successor(
                        arm,
                        spec,
                        provider,
                        first_result,
                        evidence=evidence if spec.provider == ProviderStratum.P3 else None,
                    )
                elif isinstance(arm, A0Arm) and not isinstance(arm, A1Arm):
                    admitted = self._safe_successor(arm, spec, provider, first_result)
                else:
                    admitted = self._safe_successor(
                        arm, spec, provider, first_result, evidence=evidence
                    )
                if admitted:
                    unresolved = False
                    if spec.provider in {ProviderStratum.P2, ProviderStratum.P4}:
                        if isinstance(arm, A0Arm) and not isinstance(arm, A1Arm):
                            unsafe_successor = arm.root_allocations > roots_before
                        else:
                            unsafe_successor = True
                provider.release_delayed(first_result.attempt_id)

            elif spec.schedule == Schedule.S11:
                _, first = self._new_ticket(arm, spec)
                first_result = self._dispatch(
                    arm, first, spec=spec, provider=provider, behavior="unknown_no_effect"
                )
                unresolved = True
                reconciliation_calls += 2
                t0 = datetime.now(UTC)
                current_resolution: Callable[[], bool]
                if isinstance(arm, B4Arm):
                    fence = ConventionalReconciliationFence(trial_root / "b4-fence.sqlite")
                    b4_old = fence.claim(spec.alpha, "worker-old", now=t0, lease_seconds=1)
                    b4_new = fence.claim(
                        spec.alpha,
                        "worker-new",
                        now=t0 + timedelta(seconds=2),
                        lease_seconds=5,
                    )
                    if b4_old is None or b4_new is None:
                        raise HarnessScheduleError(
                            "B4 reconciliation takeover could not be established"
                        )
                    stale_commit_accepted = fence.commit_is_current(
                        b4_old, now=t0 + timedelta(seconds=2)
                    )

                    def current_resolution() -> bool:
                        return fence.commit_is_current(b4_new, now=t0 + timedelta(seconds=2))

                else:
                    ag_old = arm.state.claim_reconciliation_lease(
                        first_result.attempt_id,
                        "worker-old",
                        now=t0,
                        lease_seconds=1,
                    )
                    ag_new = arm.state.claim_reconciliation_lease(
                        first_result.attempt_id,
                        "worker-new",
                        now=t0 + timedelta(seconds=2),
                        lease_seconds=5,
                    )
                    if ag_old is None or ag_new is None:
                        raise HarnessScheduleError(
                            "AgentGuard reconciliation takeover could not be established"
                        )
                    recon_evidence = ReconciliationEvidence(
                        status=ReconciliationStatus.STILL_UNKNOWN,
                        source="research-provider",
                        evidence_digest=digest({"trial": spec.trial_id, "worker": "stale"}),
                        observed_at=t0 + timedelta(seconds=2),
                        trust_level=EvidenceTrustLevel.PROVIDER_CORRELATED,
                    )
                    try:
                        with arm.state.resolution_lease(ag_old):
                            arm.state.record_execution_resolution(
                                first_result.attempt_id,
                                recon_evidence,
                                t0 + timedelta(seconds=2),
                            )
                        stale_commit_accepted = True
                    except ReconciliationLeaseError:
                        stale_commit_accepted = False

                    def current_resolution() -> bool:
                        with arm.state.resolution_lease(ag_new):
                            arm.state.record_execution_resolution(
                                first_result.attempt_id,
                                recon_evidence,
                                t0 + timedelta(seconds=2),
                            )
                        return True

                race_barrier = Barrier(2)
                roots_before = arm.root_allocations if isinstance(arm, A0Arm) else 1

                def resolve_current() -> bool:
                    self._await_barrier(race_barrier, trace, "current-reconciler")
                    accepted = current_resolution()
                    trace.event("s11.current-resolution", accepted=accepted)
                    return accepted

                def pressure_successor() -> bool:
                    self._await_barrier(race_barrier, trace, "successor")
                    if spec.provider == ProviderStratum.P1:
                        admitted_local = self._safe_successor(arm, spec, provider, first_result)
                    elif isinstance(arm, A0Arm) and not isinstance(arm, A1Arm):
                        admitted_local = self._safe_successor(arm, spec, provider, first_result)
                    else:
                        admitted_local = False
                    trace.event("s11.successor", admitted=admitted_local)
                    return admitted_local

                with ThreadPoolExecutor(max_workers=2) as pool:
                    resolution_future = pool.submit(resolve_current)
                    successor_future = pool.submit(pressure_successor)
                    if not resolution_future.result():
                        raise HarnessScheduleError(
                            "current reconciler lost current fencing authority"
                        )
                    admitted = successor_future.result()
                if admitted:
                    unresolved = False
                    if (
                        spec.provider != ProviderStratum.P1
                        and isinstance(arm, A0Arm)
                        and not isinstance(arm, A1Arm)
                    ):
                        unsafe_successor = arm.root_allocations > roots_before

            else:
                raise HarnessScheduleError(f"unimplemented schedule: {spec.schedule.value}")

        except HarnessScheduleError as exc:
            harness_invalid_reason = (
                f"{HarnessInvalidReason.SCHEDULE_BARRIER_FAILURE.value}:{type(exc).__name__}"
            )
            trace.event("harness.invalid", reason=harness_invalid_reason)
        except OracleIsolationError as exc:
            harness_invalid_reason = (
                f"{HarnessInvalidReason.ORACLE_UNAVAILABLE.value}:{type(exc).__name__}"
            )
            trace.event("harness.invalid", reason=harness_invalid_reason)
        except Exception as exc:
            unresolved = True
            trace.event("sut.exception", error=type(exc).__name__)

        duration = max(0.0, time.monotonic() - started)
        if isinstance(arm, A1Arm):
            counts = arm.lineage.counts(spec.alpha)
            allocations = arm.root_allocations
            independent_opportunities = counts["independent_effect_opportunities"]
            attempts = counts["attempts"]
            receipts = arm.receipts
            credentials = arm.credentials
        elif isinstance(arm, B4Arm):
            counts = arm.lineage.counts(spec.alpha)
            allocations = counts["root_or_slot_allocations"]
            independent_opportunities = counts["independent_effect_opportunities"]
            attempts = counts["attempts"]
            receipts = arm.receipts
            credentials = arm.credentials
        else:
            allocations = arm.root_allocations
            attempts = provider.sends(spec.trial_id)
            receipts = arm.receipts
            credentials = arm.credentials
            independent_opportunities = allocations

        observation = TrialObservation(
            trial_id=spec.trial_id,
            arm=spec.arm,
            provider=spec.provider,
            schedule=spec.schedule,
            replicate=spec.replicate,
            block_seed=spec.block_seed,
            alpha=spec.alpha,
            effect_key=spec.effect_key,
            root_or_slot_allocations=allocations,
            independent_live_slots_max=max(1, independent_opportunities),
            receipts_or_tickets=receipts,
            credentials=credentials,
            provider_sends=provider.sends(spec.trial_id),
            attempts=attempts,
            successor_admitted_while_predecessor_potentially_effectful=unsafe_successor,
            stale_reconciler_commit_accepted=stale_commit_accepted,
            legitimate_completion=False,
            unresolved=unresolved,
            operator_interventions=operator_interventions,
            reconciliation_calls=reconciliation_calls,
            slot_hold_seconds=duration,
            duration_seconds=duration,
            harness_invalid=harness_invalid_reason is not None,
            harness_invalid_reason=harness_invalid_reason,
        )
        trace.event(
            "trial.observation",
            harness_invalid=observation.harness_invalid,
            unresolved=observation.unresolved,
            independent_slots=observation.independent_live_slots_max,
            provider_sends=observation.provider_sends,
        )
        oracle_error = self._close_oracle(oracle_process)
        if oracle_error is not None:
            observation = replace(
                observation,
                harness_invalid=True,
                harness_invalid_reason=(
                    f"{HarnessInvalidReason.ORACLE_UNAVAILABLE.value}:{oracle_error}"
                ),
            )
            trace.event("harness.invalid", reason=observation.harness_invalid_reason)
        trace.event("trial.end", harness_invalid=observation.harness_invalid)
        trace.close()
        trace_valid, trace_error = validate_trace(trace_path, spec.trial_id)
        if not trace_valid:
            observation = replace(
                observation,
                harness_invalid=True,
                harness_invalid_reason=(
                    f"{HarnessInvalidReason.TRACE_CORRUPT.value}:{trace_error or 'unknown'}"
                ),
            )
        return observation
