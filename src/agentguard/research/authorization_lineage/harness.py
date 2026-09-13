from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
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
from .provider import SimulatedProvider

ResearchArm: TypeAlias = A0Arm | A1Arm | B4Arm
ResearchTicket: TypeAlias = AgentGuardTicket | B4Ticket
AuthorityToken: TypeAlias = AuthorityHandle | str


class HarnessProtocolError(RuntimeError):
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
            b4_ticket = cast(B4Ticket, ticket)
            return arm.dispatch(
                b4_ticket,
                trial_id=spec.trial_id,
                provider_simulator=provider,
                provider=spec.provider,
                idempotency_key=DevTrialHarness._idem(spec),
                behavior=behavior,
                parent_attempt_id=parent_attempt_id,
                allow_same_slot_retry=allow_same_slot_retry,
            )
        agentguard_ticket = cast(AgentGuardTicket, ticket)
        return arm.dispatch(
            agentguard_ticket,
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

    def run(self, spec: TrialSpec) -> TrialObservation:
        trial_root = self.root / spec.trial_id
        if trial_root.exists() and any(trial_root.iterdir()):
            raise HarnessProtocolError("DEV trial namespace must be clean")
        trial_root.mkdir(parents=True, exist_ok=True)
        provider = SimulatedProvider(trial_root / "provider.sqlite", trial_root / "oracle.sqlite")
        arm = self._arm(spec, trial_root)
        arm.register_alpha(spec.alpha, spec.effect_key)
        started = time.monotonic()
        unsafe_successor = False
        stale_commit_accepted = False
        operator_interventions = 0
        reconciliation_calls = 0
        unresolved = False

        try:
            if spec.schedule == Schedule.S0:
                _, ticket = self._new_ticket(arm, spec)
                result = self._dispatch(arm, ticket, spec=spec, provider=provider, behavior="normal")
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
                    handle = cast(AuthorityHandle, authority)
                    self._try(lambda: arm.issue_ticket(handle, spec.trial_id))

            elif spec.schedule == Schedule.S3:
                _, first = self._new_ticket(arm, spec)
                self._dispatch(arm, first, spec=spec, provider=provider, behavior="normal")
                try:
                    _, second = self._new_ticket(arm, spec)
                    self._dispatch(arm, second, spec=spec, provider=provider, behavior="normal")
                except Exception:
                    pass

            elif spec.schedule == Schedule.S4:
                def acquire_and_dispatch() -> bool:
                    try:
                        _, ticket = self._new_ticket(arm, spec)
                        return self._try(
                            lambda: self._dispatch(
                                arm, ticket, spec=spec, provider=provider, behavior="normal"
                            )
                        )
                    except Exception:
                        return False

                with ThreadPoolExecutor(max_workers=2) as pool:
                    list(pool.map(lambda _: acquire_and_dispatch(), range(2)))

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
                    except Exception:
                        pass
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
                        raise HarnessProtocolError(error)
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
                    except Exception:
                        pass
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
                if admitted:
                    unresolved = False
                    if spec.provider != ProviderStratum.P1:
                        if isinstance(arm, A0Arm) and not isinstance(arm, A1Arm):
                            unsafe_successor = arm.root_allocations > roots_before
                        else:
                            unsafe_successor = True
                if spec.schedule == Schedule.S10 and spec.provider != ProviderStratum.P1:
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
                if isinstance(arm, B4Arm):
                    fence = ConventionalReconciliationFence(trial_root / "b4-fence.sqlite")
                    old = fence.claim(spec.alpha, "worker-old", now=t0, lease_seconds=1)
                    new = fence.claim(
                        spec.alpha,
                        "worker-new",
                        now=t0 + timedelta(seconds=2),
                        lease_seconds=5,
                    )
                    if old is None or new is None:
                        raise HarnessProtocolError("B4 fence setup failed")
                    stale_commit_accepted = fence.commit_is_current(
                        old, now=t0 + timedelta(seconds=2)
                    )
                    if not fence.commit_is_current(new, now=t0 + timedelta(seconds=2)):
                        raise HarnessProtocolError("B4 current fence rejected")
                else:
                    old = arm.state.claim_reconciliation_lease(
                        first_result.attempt_id,
                        "worker-old",
                        now=t0,
                        lease_seconds=1,
                    )
                    new = arm.state.claim_reconciliation_lease(
                        first_result.attempt_id,
                        "worker-new",
                        now=t0 + timedelta(seconds=2),
                        lease_seconds=5,
                    )
                    if old is None or new is None:
                        raise HarnessProtocolError("AgentGuard fence setup failed")
                    recon_evidence = ReconciliationEvidence(
                        status=ReconciliationStatus.STILL_UNKNOWN,
                        source="research-provider",
                        evidence_digest=digest({"trial": spec.trial_id, "worker": "stale"}),
                        observed_at=t0 + timedelta(seconds=2),
                        trust_level=EvidenceTrustLevel.PROVIDER_CORRELATED,
                    )
                    try:
                        with arm.state.resolution_lease(old):
                            arm.state.record_execution_resolution(
                                first_result.attempt_id,
                                recon_evidence,
                                t0 + timedelta(seconds=2),
                            )
                        stale_commit_accepted = True
                    except ReconciliationLeaseError:
                        stale_commit_accepted = False
                    with arm.state.resolution_lease(new):
                        arm.state.record_execution_resolution(
                            first_result.attempt_id,
                            recon_evidence,
                            t0 + timedelta(seconds=2),
                        )
                roots_before = arm.root_allocations if isinstance(arm, A0Arm) else 1
                admitted = False
                if spec.provider == ProviderStratum.P1:
                    admitted = self._safe_successor(arm, spec, provider, first_result)
                elif isinstance(arm, A0Arm) and not isinstance(arm, A1Arm):
                    admitted = self._safe_successor(arm, spec, provider, first_result)
                if admitted:
                    unresolved = False
                    if spec.provider != ProviderStratum.P1:
                        unsafe_successor = arm.root_allocations > roots_before

            else:
                raise HarnessProtocolError(f"unimplemented schedule: {spec.schedule.value}")

        except HarnessProtocolError:
            raise
        except Exception:
            unresolved = True

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
            independent_opportunities = 1 if spec.provider == ProviderStratum.P1 else allocations

        return TrialObservation(
            trial_id=spec.trial_id,
            arm=spec.arm,
            provider=spec.provider,
            schedule=spec.schedule,
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
        )
