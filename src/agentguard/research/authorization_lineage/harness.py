from __future__ import annotations

import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Callable
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

from .arms import A0Arm, A1Arm, AgentGuardTicket, B4Arm, B4Ticket, DispatchRecord
from .fence import ConventionalReconciliationFence
from .ledger import LineageLedgerError
from .models import Arm, ProviderStratum, Schedule, TrialObservation, TrialSpec
from .provider import SimulatedProvider


class HarnessProtocolError(RuntimeError):
    pass


def _latest_lineage_attempt(path: Path, alpha: str) -> str:
    with sqlite3.connect(path) as connection:
        row = connection.execute(
            "SELECT attempt_id FROM attempts WHERE alpha=? ORDER BY created_at DESC LIMIT 1",
            (alpha,),
        ).fetchone()
    if row is None:
        raise HarnessProtocolError("lineage attempt missing")
    return str(row[0])


class DevTrialHarness:
    """DEV-only executor for the frozen schedules.

    It intentionally does not generate confirmatory seeds or the confirmatory manifest. The same
    schedule implementation can be invoked later by a frozen confirmatory runner after all component
    SHAs are fixed.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _arm(self, spec: TrialSpec, trial_root: Path) -> A0Arm | A1Arm | B4Arm:
        if spec.arm == Arm.A0:
            return A0Arm(trial_root / "a0")
        if spec.arm == Arm.A1:
            return A1Arm(trial_root / "a1")
        return B4Arm(trial_root / "b4")

    @staticmethod
    def _idem(spec: TrialSpec) -> str | None:
        return spec.effect_key if spec.provider == ProviderStratum.P1 else None

    @staticmethod
    def _new_ticket(
        arm: A0Arm | A1Arm | B4Arm,
        spec: TrialSpec,
    ) -> tuple[object, AgentGuardTicket | B4Ticket]:
        authority = arm.acquire_authority(spec.alpha, spec.effect_key)
        if isinstance(arm, B4Arm):
            return authority, arm.issue_ticket(spec.alpha, spec.effect_key)
        return authority, arm.issue_ticket(authority, spec.trial_id)

    @staticmethod
    def _dispatch(
        arm: A0Arm | A1Arm | B4Arm,
        ticket: AgentGuardTicket | B4Ticket,
        *,
        spec: TrialSpec,
        provider: SimulatedProvider,
        behavior: str,
        parent_attempt_id: str | None = None,
        allow_same_slot_retry: bool = False,
    ) -> DispatchRecord:
        kwargs = {
            "trial_id": spec.trial_id,
            "provider_simulator": provider,
            "provider": spec.provider,
            "idempotency_key": DevTrialHarness._idem(spec),
            "behavior": behavior,
        }
        if isinstance(arm, B4Arm):
            assert isinstance(ticket, B4Ticket)
            return arm.dispatch(
                ticket,
                **kwargs,
                parent_attempt_id=parent_attempt_id,
                allow_same_slot_retry=allow_same_slot_retry,
            )
        assert isinstance(ticket, AgentGuardTicket)
        return arm.dispatch(ticket, **kwargs)

    @staticmethod
    def _try(call: Callable[[], object]) -> bool:
        try:
            call()
            return True
        except Exception:
            # SUT rejection, timeout, deadlock surfacing, and runtime exceptions after trial start
            # are experiment outcomes, not HARNESS_INVALID exclusions.
            return False

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
                    assert not isinstance(authority, str)
                    if self._try(lambda: arm.issue_ticket(authority, spec.trial_id)):
                        raise HarnessProtocolError("exhausted AgentGuard lease unexpectedly reauthorized")

            elif spec.schedule == Schedule.S3:
                _, first = self._new_ticket(arm, spec)
                self._dispatch(arm, first, spec=spec, provider=provider, behavior="normal")
                try:
                    _, second = self._new_ticket(arm, spec)
                    self._dispatch(arm, second, spec=spec, provider=provider, behavior="normal")
                except Exception:
                    pass

            elif spec.schedule == Schedule.S4:
                def acquire() -> object:
                    return arm.acquire_authority(spec.alpha, spec.effect_key)

                with ThreadPoolExecutor(max_workers=2) as pool:
                    futures = [pool.submit(acquire) for _ in range(2)]
                    authorities: list[object] = []
                    for future in futures:
                        try:
                            authorities.append(future.result())
                        except Exception:
                            pass
                for authority in authorities:
                    try:
                        if isinstance(arm, B4Arm):
                            ticket = arm.issue_ticket(spec.alpha, spec.effect_key)
                        else:
                            assert not isinstance(authority, str)
                            ticket = arm.issue_ticket(authority, spec.trial_id)
                        self._dispatch(
                            arm, ticket, spec=spec, provider=provider, behavior="normal"
                        )
                    except Exception:
                        pass

            elif spec.schedule == Schedule.S5:
                authority, _ = self._new_ticket(arm, spec)
                if isinstance(arm, B4Arm):
                    # A second acquire must alias/refuse the same sole slot, never create a second.
                    self._try(lambda: arm.acquire_authority(spec.alpha, spec.effect_key))
                else:
                    assert not isinstance(authority, str)
                    self._try(
                        lambda: arm.service.issue_capability_lease(
                            authority.root_grant_id,
                            arm._intent_template.principal,
                            maximum_uses=1,
                        )
                    )

            elif spec.schedule == Schedule.S6:
                authority, ticket = self._new_ticket(arm, spec)
                operator_interventions += 1
                if isinstance(arm, B4Arm):
                    assert isinstance(ticket, B4Ticket)
                    attempt_id = arm.lineage.begin_attempt(spec.alpha, spec.provider)
                    # Crash occurs before dispatch. Fresh replacement pressure must not create
                    # another slot; then the exact reserved attempt is resumed.
                    self._try(lambda: arm.acquire_authority(spec.alpha, spec.effect_key))
                    arm.lineage.mark_dispatching(spec.alpha, attempt_id)
                    provider.accept(
                        trial_id=spec.trial_id,
                        provider=spec.provider,
                        attempt_id=attempt_id,
                        effect_key=spec.effect_key,
                        idempotency_key=self._idem(spec),
                    )
                    provider.commit(attempt_id)
                    arm.lineage.mark_effect(spec.alpha, attempt_id)
                else:
                    assert isinstance(ticket, AgentGuardTicket)
                    execution_id = "exec_research_reserved_" + uuid4().hex
                    verified = validate_execution_authority(
                        ticket.intent,
                        ticket.receipt,
                        ticket.credential,
                        arm.verifier,
                        execution_id=execution_id,
                        broker_grant_verifier=arm.broker.verifier,
                        current_policy=arm.policy,
                        execution_repository=arm.state,
                    )
                    error = arm.state.reserve_execution(verified, datetime.now(UTC))
                    if error is not None:
                        raise HarnessProtocolError(error)
                    if isinstance(arm, A1Arm):
                        arm.lineage.reserve_slot(spec.alpha)
                        research_attempt = arm.lineage.begin_attempt(spec.alpha, spec.provider)
                    else:
                        research_attempt = None
                    # Replacement pressure while exact reservation exists.
                    self._try(lambda: arm.acquire_authority(spec.alpha, spec.effect_key))
                    executor = arm.dispatch  # retain method identity for forensic symmetry
                    del executor
                    from .arms import _ResearchProviderExecutor

                    protected_executor = _ResearchProviderExecutor(
                        provider_simulator=provider,
                        trial_id=spec.trial_id,
                        provider=spec.provider,
                        effect_key=spec.effect_key,
                        idempotency_key=self._idem(spec),
                        behavior="normal",
                    )
                    outcome = arm.service.resume_reserved_execution(
                        execution_id,
                        ticket.intent,
                        ticket.receipt,
                        ticket.credential,
                        protected_executor,
                        current_policy=arm.policy,
                    )
                    if isinstance(arm, A1Arm) and research_attempt is not None:
                        arm.lineage.mark_dispatching(spec.alpha, research_attempt)
                        if outcome.status == ExecutionStatus.SUCCESS:
                            arm.lineage.mark_effect(spec.alpha, research_attempt)
                        else:
                            arm.lineage.mark_unknown(spec.alpha, research_attempt)

            elif spec.schedule in {Schedule.S7, Schedule.S8, Schedule.S10}:
                _, first = self._new_ticket(arm, spec)
                behavior = (
                    "commit_response_lost"
                    if spec.schedule == Schedule.S8
                    else "unknown_no_effect"
                )
                first_result = self._dispatch(
                    arm, first, spec=spec, provider=provider, behavior=behavior
                )
                unresolved = first_result.status == ExecutionStatus.UNKNOWN
                predecessor_potentially_effectful = True
                if isinstance(arm, B4Arm) and spec.provider == ProviderStratum.P1:
                    retry = arm.issue_ticket(spec.alpha, spec.effect_key)
                    self._try(
                        lambda: self._dispatch(
                            arm,
                            retry,
                            spec=spec,
                            provider=provider,
                            behavior="normal",
                            parent_attempt_id=first_result.attempt_id,
                            allow_same_slot_retry=True,
                        )
                    )
                    unresolved = False
                else:
                    roots_before = arm.root_allocations if isinstance(arm, A0Arm) else 1
                    try:
                        _, replacement = self._new_ticket(arm, spec)
                        admitted = self._try(
                            lambda: self._dispatch(
                                arm,
                                replacement,
                                spec=spec,
                                provider=provider,
                                behavior="normal",
                            )
                        )
                        if admitted and predecessor_potentially_effectful:
                            if isinstance(arm, A0Arm) and not isinstance(arm, A1Arm):
                                unsafe_successor = arm.root_allocations > roots_before
                            else:
                                unsafe_successor = True
                            unresolved = False
                    except Exception:
                        pass
                if spec.schedule == Schedule.S10 and spec.provider in {
                    ProviderStratum.P2,
                    ProviderStratum.P4,
                }:
                    # Cancellation is not proof of no effect: release the original after replacement
                    # pressure to test whether the system created two effect opportunities.
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
                if isinstance(arm, B4Arm):
                    if spec.provider == ProviderStratum.P1:
                        retry = arm.issue_ticket(spec.alpha, spec.effect_key)
                        self._try(
                            lambda: self._dispatch(
                                arm,
                                retry,
                                spec=spec,
                                provider=provider,
                                behavior="normal",
                                parent_attempt_id=first_result.attempt_id,
                                allow_same_slot_retry=True,
                            )
                        )
                        unresolved = False
                    elif spec.provider == ProviderStratum.P3:
                        arm.lineage.apply_no_effect_evidence(spec.alpha, evidence, spec.provider)
                        successor = arm.issue_ticket(spec.alpha, spec.effect_key)
                        self._try(
                            lambda: self._dispatch(
                                arm,
                                successor,
                                spec=spec,
                                provider=provider,
                                behavior="normal",
                                parent_attempt_id=first_result.attempt_id,
                            )
                        )
                        unresolved = False
                else:
                    roots_before = arm.root_allocations
                    try:
                        _, replacement = self._new_ticket(arm, spec)
                        admitted = self._try(
                            lambda: self._dispatch(
                                arm,
                                replacement,
                                spec=spec,
                                provider=provider,
                                behavior="normal",
                            )
                        )
                        if admitted and spec.provider != ProviderStratum.P3:
                            unsafe_successor = arm.root_allocations > roots_before
                        unresolved = not admitted
                    except Exception:
                        pass
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
                    evidence = ReconciliationEvidence(
                        status=ReconciliationStatus.STILL_UNKNOWN,
                        source="research-provider",
                        evidence_digest=digest(
                            {"trial": spec.trial_id, "worker": "stale"}
                        ),
                        observed_at=t0 + timedelta(seconds=2),
                        trust_level=EvidenceTrustLevel.PROVIDER_CORRELATED,
                    )
                    try:
                        with arm.state.resolution_lease(old):
                            arm.state.record_execution_resolution(
                                first_result.attempt_id,
                                evidence,
                                t0 + timedelta(seconds=2),
                            )
                        stale_commit_accepted = True
                    except ReconciliationLeaseError:
                        stale_commit_accepted = False
                    with arm.state.resolution_lease(new):
                        arm.state.record_execution_resolution(
                            first_result.attempt_id,
                            evidence,
                            t0 + timedelta(seconds=2),
                        )
                # Successor pressure after stale-worker takeover remains governed by the same rules.
                if isinstance(arm, B4Arm) and spec.provider == ProviderStratum.P1:
                    retry = arm.issue_ticket(spec.alpha, spec.effect_key)
                    self._try(
                        lambda: self._dispatch(
                            arm,
                            retry,
                            spec=spec,
                            provider=provider,
                            behavior="normal",
                            parent_attempt_id=first_result.attempt_id,
                            allow_same_slot_retry=True,
                        )
                    )
                    unresolved = False
                elif isinstance(arm, A0Arm) and not isinstance(arm, A1Arm):
                    roots_before = arm.root_allocations
                    try:
                        _, replacement = self._new_ticket(arm, spec)
                        if self._try(
                            lambda: self._dispatch(
                                arm,
                                replacement,
                                spec=spec,
                                provider=provider,
                                behavior="normal",
                            )
                        ):
                            unsafe_successor = arm.root_allocations > roots_before
                            unresolved = False
                    except Exception:
                        pass

            else:
                raise HarnessProtocolError(f"unimplemented schedule: {spec.schedule.value}")

        except HarnessProtocolError:
            raise
        except Exception:
            # Unexpected SUT failures after a valid schedule begins remain outcomes.
            unresolved = True

        duration = max(0.0, time.monotonic() - started)
        if isinstance(arm, A0Arm) and not isinstance(arm, A1Arm):
            allocations = arm.root_allocations
            attempts = provider.sends(spec.trial_id)
            receipts = arm.receipts
            credentials = arm.credentials
        elif isinstance(arm, A1Arm):
            counts = arm.lineage.counts(spec.alpha)
            allocations = counts["root_or_slot_allocations"]
            attempts = counts["attempts"]
            receipts = arm.receipts
            credentials = arm.credentials
        else:
            counts = arm.lineage.counts(spec.alpha)
            allocations = counts["root_or_slot_allocations"]
            attempts = counts["attempts"]
            receipts = arm.receipts
            credentials = arm.credentials
        return TrialObservation(
            trial_id=spec.trial_id,
            arm=spec.arm,
            provider=spec.provider,
            schedule=spec.schedule,
            alpha=spec.alpha,
            effect_key=spec.effect_key,
            root_or_slot_allocations=allocations,
            independent_live_slots_max=max(1, allocations),
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
