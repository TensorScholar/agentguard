from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal
from uuid import uuid4

import yaml

from agentguard.adapters.broker import MockCredentialBroker
from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.storage.sqlite import SQLiteFencedReconciliationState
from agentguard.application import AgentGuardService
from agentguard.domain import (
    ActionIntent,
    AuthorityReference,
    CapabilityScope,
    CredentialGrant,
    CredentialRequest,
    DecisionReceipt,
    ExecutionStatus,
    PolicyDocument,
    ProtectedExecutionResult,
    VerifiedExecution,
)
from agentguard.engine.canonical import digest
from agentguard.ports import AmbiguousExecutionError, ProtectedExecutor

from .ledger import AuthorizationInstanceLedger, LineageLedgerError
from .models import ProviderEvidence, ProviderStratum
from .provider import SimulatedProvider

DispatchBehavior = Literal["normal", "unknown_no_effect", "commit_response_lost", "delayed"]

_B4_AUDIENCE = "payments.internal"
_B4_SCOPES = frozenset({"refund:create"})
_B4_TENANT = "acme"
_B4_CREDENTIAL_TTL_SECONDS = 30


@dataclass(frozen=True)
class AuthorityHandle:
    alpha: str
    effect_key: str
    root_grant_id: str
    lease_id: str
    reference: AuthorityReference


@dataclass(frozen=True)
class AgentGuardTicket:
    authority: AuthorityHandle
    intent: ActionIntent
    receipt: DecisionReceipt
    credential: CredentialGrant


@dataclass(frozen=True)
class B4CredentialBinding:
    audience: str
    scopes: frozenset[str]
    tenant_id: str
    issued_at: datetime
    expires_at: datetime


@dataclass(frozen=True)
class B4Ticket:
    alpha: str
    effect_key: str
    ticket_id: str
    credential: B4CredentialBinding


@dataclass(frozen=True)
class DispatchRecord:
    attempt_id: str
    status: ExecutionStatus
    potentially_effectful: bool
    lineage_attempt_id: str | None = None


class _ResearchProviderExecutor(ProtectedExecutor):
    """Thin study provider adapter behind AgentGuard's real protected execution boundary."""

    def __init__(
        self,
        *,
        provider_simulator: SimulatedProvider,
        trial_id: str,
        provider: ProviderStratum,
        effect_key: str,
        idempotency_key: str | None,
        behavior: DispatchBehavior,
    ) -> None:
        self.provider_simulator = provider_simulator
        self.trial_id = trial_id
        self.provider = provider
        self.effect_key = effect_key
        self.idempotency_key = idempotency_key
        self.behavior = behavior
        self.attempt_id: str | None = None

    def execute(self, verified_execution: VerifiedExecution) -> ProtectedExecutionResult:
        execution_id = verified_execution.execution_id
        self.attempt_id = execution_id
        self.provider_simulator.accept(
            trial_id=self.trial_id,
            provider=self.provider,
            attempt_id=execution_id,
            effect_key=self.effect_key,
            idempotency_key=self.idempotency_key,
            delayed=self.behavior == "delayed",
        )
        if self.behavior == "normal":
            self.provider_simulator.commit(execution_id)
            return ProtectedExecutionResult(
                status=ExecutionStatus.SUCCESS,
                result_digest=digest({"trial_id": self.trial_id, "attempt_id": execution_id}),
            )
        if self.behavior == "commit_response_lost":
            self.provider_simulator.commit(execution_id)
            raise AmbiguousExecutionError("research.response_lost_after_commit")
        if self.behavior == "delayed":
            self.provider_simulator.set_delayed(execution_id)
            raise AmbiguousExecutionError("research.delayed_provider_effect")
        raise AmbiguousExecutionError("research.ambiguous_without_observed_effect")


class A0Arm:
    """Pinned current-AgentGuard arm using the real core protected execution service.

    Provider behavior is supplied by the common frozen study simulator. S11 uses AgentGuard's real
    `SQLiteFencedReconciliationState`. The arm adds no token-independent alpha dedup state.
    """

    def __init__(self, root: Path) -> None:
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.state = SQLiteFencedReconciliationState(root / "agentguard.sqlite")
        self.signer = Ed25519Signer.generate("research-decision-ed25519")
        self.verifier = Ed25519Verifier({self.signer.key_id: self.signer.public_key()})
        self.authority_signer = Ed25519Signer.generate("research-authority-ed25519")
        self.authority_verifier = Ed25519Verifier(
            {self.authority_signer.key_id: self.authority_signer.public_key()}
        )
        self.broker = MockCredentialBroker()
        self.service = AgentGuardService(
            self.signer,
            self.verifier,
            self.state,
            self.broker.verifier,
            authority_verifier=self.authority_verifier,
            require_authority=True,
        )
        resources = Path(__file__).parents[2] / "resources"
        self._intent_template = ActionIntent.model_validate_json(
            (resources / "demo-intent.json").read_text()
        )
        policy_raw = yaml.safe_load((resources / "default_policy_v2.yaml").read_text())
        self.policy = PolicyDocument.model_validate_json(json.dumps(policy_raw))
        self.root_allocations = 0
        self.receipts = 0
        self.credentials = 0

    def register_alpha(self, alpha: str, effect_key: str) -> None:
        del alpha, effect_key

    @staticmethod
    def _scope() -> CapabilityScope:
        return CapabilityScope(
            capabilities=frozenset({"financial_mutation"}),
            protocols=frozenset({"mcp"}),
            servers=frozenset({"customer-operations"}),
            tools=frozenset({"refund.create"}),
            operations=frozenset({"call"}),
            resource_types=frozenset({"order"}),
            resource_ids=None,
            maximum_calls=1,
            delegable=False,
            maximum_delegation_depth=0,
        )

    def acquire_authority(self, alpha: str, effect_key: str) -> AuthorityHandle:
        del alpha
        principal = self._intent_template.principal
        root = self.service.issue_root_authority(principal, self._scope(), self.authority_signer)
        lease = self.service.issue_capability_lease(
            root.grant_id, principal, maximum_uses=1, ttl_seconds=300
        )
        reference = self.service.authority_reference(root.grant_id, lease.lease_id)
        self.root_allocations += 1
        return AuthorityHandle(
            alpha="A0-untracked",
            effect_key=effect_key,
            root_grant_id=root.grant_id,
            lease_id=lease.lease_id,
            reference=reference,
        )

    def _intent(self, handle: AuthorityHandle, trial_id: str) -> ActionIntent:
        resource = self._intent_template.resource
        assert resource is not None
        trial_resource_id = "order-" + digest(trial_id).split(":", 1)[1][:16]
        updated_resource = resource.model_copy(update={"id": trial_resource_id})
        updated_arguments = dict(self._intent_template.arguments)
        updated_arguments["order_id"] = trial_resource_id
        return self._intent_template.model_copy(
            deep=True,
            update={
                "request_id": "req_" + uuid4().hex,
                "trace_id": "trc_" + uuid4().hex,
                "resource": updated_resource,
                "arguments": updated_arguments,
                "authority": handle.reference,
                "requested_at": datetime.now(UTC),
            },
        )

    def issue_ticket(self, handle: AuthorityHandle, trial_id: str) -> AgentGuardTicket:
        intent = self._intent(handle, trial_id)
        receipt = self.service.authorize(intent, self.policy, ttl_seconds=300)
        self.receipts += 1
        ceiling = receipt.credential_ceiling
        if ceiling is None:
            raise RuntimeError("research.expected_credential_ceiling")
        request = CredentialRequest(
            request_id="credreq_" + uuid4().hex,
            trace_id=receipt.trace_id,
            decision_id=receipt.decision_id,
            audience=ceiling.audience,
            scopes=ceiling.scopes,
            requested_ttl_seconds=min(30, ceiling.maximum_ttl_seconds),
            tenant_id=ceiling.tenant_id,
        )
        credential = self.service.request_credential(intent, receipt, request, self.broker)
        self.credentials += 1
        return AgentGuardTicket(handle, intent, receipt, credential)

    def dispatch(
        self,
        ticket: AgentGuardTicket,
        *,
        trial_id: str,
        provider_simulator: SimulatedProvider,
        provider: ProviderStratum,
        idempotency_key: str | None,
        behavior: DispatchBehavior,
    ) -> DispatchRecord:
        executor = _ResearchProviderExecutor(
            provider_simulator=provider_simulator,
            trial_id=trial_id,
            provider=provider,
            effect_key=ticket.authority.effect_key,
            idempotency_key=idempotency_key,
            behavior=behavior,
        )
        outcome = self.service.execute_protected(
            ticket.intent,
            ticket.receipt,
            ticket.credential,
            executor,
            current_policy=self.policy,
        )
        if executor.attempt_id is None:
            raise RuntimeError("research.provider_not_invoked")
        return DispatchRecord(
            attempt_id=executor.attempt_id,
            status=outcome.status,
            potentially_effectful=True,
        )

    def provider_evidence(
        self, provider_simulator: SimulatedProvider, attempt_id: str
    ) -> ProviderEvidence:
        return provider_simulator.status(attempt_id)


class A1Arm(A0Arm):
    """A0 plus the minimum frozen token-independent authorization-instance state."""

    def __init__(self, root: Path) -> None:
        super().__init__(root / "agentguard")
        self.lineage = AuthorizationInstanceLedger(root / "lineage.sqlite")

    def register_alpha(self, alpha: str, effect_key: str) -> None:
        self.lineage.register(alpha, effect_key)

    def _issue_fresh_bound_authority(self, alpha: str, effect_key: str) -> AuthorityHandle:
        principal = self._intent_template.principal
        root = self.service.issue_root_authority(principal, self._scope(), self.authority_signer)
        lease = self.service.issue_capability_lease(
            root.grant_id, principal, maximum_uses=1, ttl_seconds=300
        )
        reference = self.service.authority_reference(root.grant_id, lease.lease_id)
        self.root_allocations += 1
        return AuthorityHandle(alpha, effect_key, root.grant_id, lease.lease_id, reference)

    def acquire_authority(self, alpha: str, effect_key: str) -> AuthorityHandle:
        self.lineage.register(alpha, effect_key)
        claim = "claim_" + uuid4().hex
        if self.lineage.claim_root(alpha, claim):
            handle = self._issue_fresh_bound_authority(alpha, effect_key)
            encoded = handle.root_grant_id + "|" + handle.lease_id
            self.lineage.bind_root(alpha, claim, encoded)
        encoded = self.lineage.root_handle(alpha)
        if encoded is None:
            raise LineageLedgerError("lineage.root_claim_incomplete")
        root_id, lease_id = encoded.split("|", 1)
        reference = self.service.authority_reference(root_id, lease_id)
        return AuthorityHandle(alpha, effect_key, root_id, lease_id, reference)

    def _dispatch_pre_admitted(
        self,
        *,
        lineage_attempt_id: str,
        ticket: AgentGuardTicket,
        trial_id: str,
        provider_simulator: SimulatedProvider,
        provider: ProviderStratum,
        idempotency_key: str | None,
        behavior: DispatchBehavior,
    ) -> DispatchRecord:
        alpha = ticket.authority.alpha
        self.lineage.mark_dispatching(alpha, lineage_attempt_id)
        try:
            record = A0Arm.dispatch(
                self,
                ticket,
                trial_id=trial_id,
                provider_simulator=provider_simulator,
                provider=provider,
                idempotency_key=idempotency_key,
                behavior=behavior,
            )
        except Exception:
            self.lineage.mark_unknown(alpha, lineage_attempt_id)
            raise
        if record.status == ExecutionStatus.SUCCESS:
            self.lineage.mark_effect(alpha, lineage_attempt_id)
        else:
            self.lineage.mark_unknown(alpha, lineage_attempt_id)
        return DispatchRecord(
            attempt_id=record.attempt_id,
            status=record.status,
            potentially_effectful=record.potentially_effectful,
            lineage_attempt_id=lineage_attempt_id,
        )

    def dispatch(
        self,
        ticket: AgentGuardTicket,
        *,
        trial_id: str,
        provider_simulator: SimulatedProvider,
        provider: ProviderStratum,
        idempotency_key: str | None,
        behavior: DispatchBehavior,
    ) -> DispatchRecord:
        alpha = ticket.authority.alpha
        self.lineage.reserve_slot(alpha)
        lineage_attempt_id = self.lineage.begin_attempt(
            alpha,
            provider,
            idempotency_key=idempotency_key,
        )
        return self._dispatch_pre_admitted(
            lineage_attempt_id=lineage_attempt_id,
            ticket=ticket,
            trial_id=trial_id,
            provider_simulator=provider_simulator,
            provider=provider,
            idempotency_key=idempotency_key,
            behavior=behavior,
        )

    @staticmethod
    def _lineage_evidence(
        lineage_attempt_id: str, provider_evidence: ProviderEvidence
    ) -> ProviderEvidence:
        """Translate provider/execution correlation into the alpha-ledger attempt namespace."""

        return ProviderEvidence(
            attempt_id=lineage_attempt_id,
            status=provider_evidence.status,
            authoritative=provider_evidence.authoritative,
            no_effect_certified=provider_evidence.no_effect_certified,
            predecessor_fenced=provider_evidence.predecessor_fenced,
        )

    def dispatch_successor(
        self,
        *,
        alpha: str,
        effect_key: str,
        predecessor_lineage_attempt_id: str,
        evidence: ProviderEvidence | None,
        trial_id: str,
        provider_simulator: SimulatedProvider,
        provider: ProviderStratum,
        idempotency_key: str | None,
        behavior: DispatchBehavior,
    ) -> DispatchRecord:
        if provider == ProviderStratum.P1:
            lineage_attempt_id = self.lineage.begin_attempt(
                alpha,
                provider,
                parent_attempt_id=predecessor_lineage_attempt_id,
                idempotency_key=idempotency_key,
                allow_same_slot_retry=True,
            )
        else:
            if evidence is None:
                raise LineageLedgerError("lineage.successor_requires_evidence")
            self.lineage.apply_no_effect_evidence(
                alpha,
                self._lineage_evidence(predecessor_lineage_attempt_id, evidence),
                provider,
            )
            lineage_attempt_id = self.lineage.begin_attempt(
                alpha,
                provider,
                parent_attempt_id=predecessor_lineage_attempt_id,
                idempotency_key=idempotency_key,
            )
        handle = self._issue_fresh_bound_authority(alpha, effect_key)
        ticket = self.issue_ticket(handle, trial_id)
        return self._dispatch_pre_admitted(
            lineage_attempt_id=lineage_attempt_id,
            ticket=ticket,
            trial_id=trial_id,
            provider_simulator=provider_simulator,
            provider=provider,
            idempotency_key=idempotency_key,
            behavior=behavior,
        )


class B4Arm:
    """Strong conventional transactional ledger baseline without AgentGuard receipt machinery."""

    def __init__(self, root: Path) -> None:
        root.mkdir(parents=True, exist_ok=True)
        self.lineage = AuthorizationInstanceLedger(root / "b4.sqlite")
        self.receipts = 0
        self.credentials = 0

    def register_alpha(self, alpha: str, effect_key: str) -> None:
        self.lineage.register(alpha, effect_key)

    def acquire_authority(self, alpha: str, effect_key: str) -> str:
        snapshot = self.lineage.register(alpha, effect_key)
        self.lineage.reserve_slot(alpha)
        return snapshot.slot_id

    def issue_ticket(self, alpha: str, effect_key: str) -> B4Ticket:
        snapshot = self.lineage.snapshot(alpha)
        if snapshot.effect_key != effect_key:
            raise LineageLedgerError("lineage.effect_key_mismatch")
        now = datetime.now(UTC)
        credential = B4CredentialBinding(
            audience=_B4_AUDIENCE,
            scopes=_B4_SCOPES,
            tenant_id=_B4_TENANT,
            issued_at=now,
            expires_at=now + timedelta(seconds=_B4_CREDENTIAL_TTL_SECONDS),
        )
        self.receipts += 1
        self.credentials += 1
        return B4Ticket(alpha, effect_key, "ticket_" + uuid4().hex, credential)

    @staticmethod
    def _validate_ticket(ticket: B4Ticket) -> None:
        now = datetime.now(UTC)
        credential = ticket.credential
        if credential.expires_at <= now:
            raise LineageLedgerError("b4.credential_expired")
        if (
            credential.audience != _B4_AUDIENCE
            or credential.scopes != _B4_SCOPES
            or credential.tenant_id != _B4_TENANT
        ):
            raise LineageLedgerError("b4.credential_binding_mismatch")

    def dispatch(
        self,
        ticket: B4Ticket,
        *,
        trial_id: str,
        provider_simulator: SimulatedProvider,
        provider: ProviderStratum,
        idempotency_key: str | None,
        behavior: DispatchBehavior,
        parent_attempt_id: str | None = None,
        allow_same_slot_retry: bool = False,
    ) -> DispatchRecord:
        self._validate_ticket(ticket)
        attempt_id = self.lineage.begin_attempt(
            ticket.alpha,
            provider,
            parent_attempt_id=parent_attempt_id,
            idempotency_key=idempotency_key,
            allow_same_slot_retry=allow_same_slot_retry,
        )
        self.lineage.mark_dispatching(ticket.alpha, attempt_id)
        provider_simulator.accept(
            trial_id=trial_id,
            provider=provider,
            attempt_id=attempt_id,
            effect_key=ticket.effect_key,
            idempotency_key=idempotency_key,
            delayed=behavior == "delayed",
        )
        if behavior == "normal":
            provider_simulator.commit(attempt_id)
            self.lineage.mark_effect(ticket.alpha, attempt_id)
            return DispatchRecord(attempt_id, ExecutionStatus.SUCCESS, True, attempt_id)
        if behavior == "commit_response_lost":
            provider_simulator.commit(attempt_id)
        elif behavior == "delayed":
            provider_simulator.set_delayed(attempt_id)
        self.lineage.mark_unknown(ticket.alpha, attempt_id)
        return DispatchRecord(attempt_id, ExecutionStatus.UNKNOWN, True, attempt_id)

    def dispatch_successor(
        self,
        *,
        alpha: str,
        effect_key: str,
        predecessor_attempt_id: str,
        evidence: ProviderEvidence | None,
        trial_id: str,
        provider_simulator: SimulatedProvider,
        provider: ProviderStratum,
        idempotency_key: str | None,
        behavior: DispatchBehavior,
    ) -> DispatchRecord:
        if provider == ProviderStratum.P1:
            ticket = self.issue_ticket(alpha, effect_key)
            return self.dispatch(
                ticket,
                trial_id=trial_id,
                provider_simulator=provider_simulator,
                provider=provider,
                idempotency_key=idempotency_key,
                behavior=behavior,
                parent_attempt_id=predecessor_attempt_id,
                allow_same_slot_retry=True,
            )
        if evidence is None:
            raise LineageLedgerError("lineage.successor_requires_evidence")
        self.lineage.apply_no_effect_evidence(alpha, evidence, provider)
        ticket = self.issue_ticket(alpha, effect_key)
        return self.dispatch(
            ticket,
            trial_id=trial_id,
            provider_simulator=provider_simulator,
            provider=provider,
            idempotency_key=idempotency_key,
            behavior=behavior,
            parent_attempt_id=predecessor_attempt_id,
        )
