from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from agentguard.domain import (
    ActionIntent,
    ApprovalReceipt,
    AuditEvent,
    AuditEventType,
    AuthorityGrant,
    AuthorityGrantStatus,
    AuthorityReference,
    CapabilityLease,
    CapabilityLeaseStatus,
    CapabilityScope,
    CredentialGrant,
    CredentialRequest,
    DecisionReceipt,
    EnforcementMode,
    ExecutionAttestation,
    ExecutionOutcome,
    ExecutionRecord,
    ExecutionResolution,
    ExecutionState,
    ExecutionStatus,
    FieldIntegrityBinding,
    PolicyDocument,
    PreparedExecution,
    PreparedExecutionStatus,
    Principal,
    ProtectedExecutionResult,
    ReconciliationStatus,
    VerifiedExecution,
)
from agentguard.engine.attestation import (
    attestation_metadata,
    issue_execution_attestation,
)
from agentguard.engine.authority import (
    AuthorityError,
    authority_chain_digest,
    validate_authority_chain,
)
from agentguard.engine.authority import (
    delegate_authority as delegate_authority_grant,
)
from agentguard.engine.authority import (
    issue_root_authority as issue_root_authority_grant,
)
from agentguard.engine.canonical import digest
from agentguard.engine.causal import CausalIntegrityError, validate_causal_context
from agentguard.engine.credentials import (
    CredentialVerificationError,
    validate_credential_request,
    verify_credential_grant,
)
from agentguard.engine.execution import (
    ExecutionGuardError,
    authorize_execution,
    execution_authority_digest,
    prepared_execution_binding_digest,
    validate_execution_authority,
)
from agentguard.engine.field_integrity import FieldIntegrityError, validate_field_integrity
from agentguard.engine.policy import evaluate_policy
from agentguard.engine.receipts import (
    ReceiptVerificationError,
    issue_approval_receipt,
    issue_decision_receipt,
    verify_approval_receipt,
    verify_decision_receipt,
    verify_intent_binding,
)
from agentguard.ports import (
    AmbiguousExecutionError,
    BrokerGrantVerifier,
    CredentialBroker,
    DefiniteExecutionFailure,
    ExecutionReconciler,
    ProtectedExecutor,
    SignatureVerifier,
    Signer,
    StateRepository,
)


class ExecutionPersistenceError(RuntimeError):
    pass


class AgentGuardService:
    def __init__(
        self,
        signer: Signer,
        verifier: SignatureVerifier,
        state: StateRepository,
        broker_grant_verifier: BrokerGrantVerifier | None = None,
        authority_verifier: SignatureVerifier | None = None,
        provenance_verifier: SignatureVerifier | None = None,
        release_verifier: SignatureVerifier | None = None,
        *,
        require_authority: bool = False,
    ) -> None:
        self.signer = signer
        self.verifier = verifier
        self.state = state
        self.broker_grant_verifier = broker_grant_verifier
        self.authority_verifier = authority_verifier or verifier
        self.provenance_verifier = provenance_verifier
        self.release_verifier = release_verifier
        self.require_authority = require_authority

    def _event(self, event_type: AuditEventType, intent: ActionIntent, **kw: Any) -> AuditEvent:
        timestamp = kw.pop("timestamp", datetime.now(UTC))
        return AuditEvent(
            event_id="evt_" + uuid4().hex,
            event_type=event_type,
            timestamp=timestamp,
            trace_id=intent.trace_id,
            request_id=intent.request_id,
            source="agentguard",
            **kw,
        )

    def _authority_event(
        self,
        event_type: AuditEventType,
        *,
        trace_id: str,
        reason_code: str | None = None,
        data: dict[str, str | int | bool | None] | None = None,
    ) -> AuditEvent:
        return AuditEvent(
            event_id="evt_" + uuid4().hex,
            event_type=event_type,
            timestamp=datetime.now(UTC),
            trace_id=trace_id,
            source="agentguard",
            reason_code=reason_code,
            data=data or {},
        )

    def _load_authority_chain(self, grant_id: str) -> tuple[AuthorityGrant, ...]:
        reversed_chain: list[AuthorityGrant] = []
        visited: set[str] = set()
        current_id: str | None = grant_id
        while current_id is not None:
            if current_id in visited or len(reversed_chain) > 16:
                raise AuthorityError("authority.chain_cycle")
            visited.add(current_id)
            record = self.state.get_authority_grant(current_id)
            if record is None:
                raise AuthorityError("authority.grant_missing")
            if record.status != AuthorityGrantStatus.ACTIVE:
                raise AuthorityError("authority.grant_revoked")
            reversed_chain.append(record.grant)
            current_id = record.grant.parent_grant_id
        return tuple(reversed(reversed_chain))

    def _validate_intent_authority(
        self,
        intent: ActionIntent,
        *,
        allow_consumed_lease: bool = False,
    ) -> tuple[AuthorityGrant, ...] | None:
        reference = intent.authority
        if reference is None:
            if self.require_authority:
                raise AuthorityError("authority.required")
            return None
        chain = self._load_authority_chain(reference.grant_id)
        validate_authority_chain(chain, intent, self.authority_verifier)
        if authority_chain_digest(chain) != reference.chain_digest:
            raise AuthorityError("authority.chain_digest_mismatch")
        lease = self.state.get_capability_lease(reference.lease_id)
        if lease is None:
            raise AuthorityError("authority.lease_missing")
        if lease.grant_id != reference.grant_id:
            raise AuthorityError("authority.lease_grant_mismatch")
        now = datetime.now(UTC)
        if lease.expires_at <= now:
            raise AuthorityError("authority.lease_expired")
        allowed_statuses = {CapabilityLeaseStatus.ACTIVE}
        if allow_consumed_lease:
            allowed_statuses.add(CapabilityLeaseStatus.EXHAUSTED)
        if lease.status not in allowed_statuses:
            raise AuthorityError("authority.lease_unavailable")
        if not allow_consumed_lease and lease.remaining_uses < 1:
            raise AuthorityError("authority.lease_exhausted")
        return chain

    def authority_reference(self, grant_id: str, lease_id: str) -> AuthorityReference:
        chain = self._load_authority_chain(grant_id)
        lease = self.state.get_capability_lease(lease_id)
        if lease is None or lease.grant_id != grant_id:
            raise AuthorityError("authority.lease_grant_mismatch")
        return AuthorityReference(
            grant_id=grant_id,
            lease_id=lease_id,
            chain_digest=authority_chain_digest(chain),
        )

    def issue_root_authority(
        self,
        subject: Principal,
        scope: CapabilityScope,
        authority_signer: Signer,
        *,
        ttl_seconds: int = 3600,
        issuer: str = "agentguard",
    ) -> AuthorityGrant:
        grant = issue_root_authority_grant(
            subject,
            scope,
            authority_signer,
            ttl_seconds=ttl_seconds,
            issuer=issuer,
        )
        self.state.store_authority_grant(grant)
        self.state.append(
            self._authority_event(
                AuditEventType.AUTHORITY_GRANTED,
                trace_id=grant.grant_id,
                data={
                    "grant_id": grant.grant_id,
                    "subject_agent_id": grant.subject.agent_id,
                    "maximum_calls": grant.scope.maximum_calls,
                },
            )
        )
        return grant

    def delegate_authority(
        self,
        parent_grant_id: str,
        delegator: Principal,
        subject: Principal,
        scope: CapabilityScope,
        authority_signer: Signer,
        *,
        ttl_seconds: int = 1800,
    ) -> AuthorityGrant:
        parent_record = self.state.get_authority_grant(parent_grant_id)
        if parent_record is None or parent_record.status != AuthorityGrantStatus.ACTIVE:
            raise AuthorityError("authority.parent_not_active")
        if delegator != parent_record.grant.subject:
            raise AuthorityError("authority.delegator_mismatch")
        grant = delegate_authority_grant(
            parent_record.grant,
            subject,
            scope,
            authority_signer,
            self.authority_verifier,
            ttl_seconds=ttl_seconds,
        )
        try:
            self.state.store_authority_grant(grant)
        except RuntimeError as exc:
            if str(exc).startswith("authority."):
                raise AuthorityError(str(exc)) from exc
            raise
        self.state.append(
            self._authority_event(
                AuditEventType.AUTHORITY_DELEGATED,
                trace_id=grant.grant_id,
                data={
                    "grant_id": grant.grant_id,
                    "parent_grant_id": parent_grant_id,
                    "depth": grant.depth,
                },
            )
        )
        return grant

    def revoke_authority(self, grant_id: str, *, reason: str) -> None:
        record = self.state.revoke_authority_grant(grant_id, datetime.now(UTC), reason)
        self.state.append(
            self._authority_event(
                AuditEventType.AUTHORITY_REVOKED,
                trace_id=grant_id,
                reason_code=reason,
                data={"grant_id": record.grant.grant_id},
            )
        )

    def issue_capability_lease(
        self,
        grant_id: str,
        holder: Principal,
        *,
        maximum_uses: int,
        ttl_seconds: int = 300,
    ) -> CapabilityLease:
        record = self.state.get_authority_grant(grant_id)
        if record is None or record.status != AuthorityGrantStatus.ACTIVE:
            raise AuthorityError("authority.grant_not_active")
        if holder != record.grant.subject:
            raise AuthorityError("authority.holder_mismatch")
        now = datetime.now(UTC)
        if now >= record.grant.expires_at:
            raise AuthorityError("authority.grant_expired")
        if maximum_uses < 1 or maximum_uses > record.grant.scope.maximum_calls:
            raise AuthorityError("authority.lease_uses_exceed_scope")
        if ttl_seconds < 1:
            raise AuthorityError("authority.lease_ttl_invalid")
        expires_at = min(
            now + timedelta(seconds=ttl_seconds),
            record.grant.expires_at,
        )
        lease = CapabilityLease(
            lease_id="lease_" + uuid4().hex,
            grant_id=grant_id,
            maximum_uses=maximum_uses,
            remaining_uses=maximum_uses,
            issued_at=now,
            expires_at=expires_at,
            status=CapabilityLeaseStatus.ACTIVE,
        )
        try:
            self.state.store_capability_lease(lease)
        except RuntimeError as exc:
            if str(exc).startswith("authority."):
                raise AuthorityError(str(exc)) from exc
            raise
        self.state.append(
            self._authority_event(
                AuditEventType.CAPABILITY_LEASE_ISSUED,
                trace_id=lease.lease_id,
                data={
                    "lease_id": lease.lease_id,
                    "grant_id": grant_id,
                    "maximum_uses": maximum_uses,
                },
            )
        )
        return lease

    def revoke_capability_lease(self, lease_id: str) -> None:
        lease = self.state.revoke_capability_lease(lease_id, datetime.now(UTC))
        self.state.append(
            self._authority_event(
                AuditEventType.AUTHORITY_REVOKED,
                trace_id=lease_id,
                reason_code="authority.lease_revoked",
                data={"lease_id": lease_id, "grant_id": lease.grant_id},
            )
        )

    def reconcile_execution(
        self,
        execution_id: str,
        reconciler: ExecutionReconciler,
    ) -> ExecutionResolution:
        execution = self.state.get_execution(execution_id)
        if execution is None:
            raise ExecutionGuardError("execution.record_missing")
        if execution.state != ExecutionState.UNKNOWN:
            raise ExecutionGuardError("reconciliation.execution_not_unknown")
        self.state.append(
            self._authority_event(
                AuditEventType.EXECUTION_RECONCILIATION_STARTED,
                trace_id=execution.trace_id,
                data={"execution_id": execution_id},
            )
        )
        evidence = reconciler.reconcile(execution)
        if evidence.status == ReconciliationStatus.CONFLICT:
            raise ExecutionGuardError("reconciliation.adapter_cannot_assert_conflict")
        resolution = self.state.record_execution_resolution(
            execution_id, evidence, datetime.now(UTC)
        )
        self.state.append(
            AuditEvent(
                event_id="evt_" + uuid4().hex,
                event_type=AuditEventType.EXECUTION_RECONCILED,
                timestamp=datetime.now(UTC),
                trace_id=execution.trace_id,
                request_id=execution.request_id,
                decision_id=execution.decision_id,
                execution_id=execution.execution_id,
                source="agentguard",
                reason_code=resolution.error_code,
                data={
                    "resolution_id": resolution.resolution_id,
                    "status": resolution.status.value,
                    "evidence_digest": resolution.evidence_digest,
                    "trust_level": resolution.trust_level.value,
                },
            )
        )
        return resolution

    def issue_execution_attestation(
        self,
        execution_id: str,
        attestation_signer: Signer,
    ) -> ExecutionAttestation:
        execution = self.state.get_execution(execution_id)
        if execution is None:
            raise ExecutionGuardError("execution.record_missing")
        resolution = self.state.get_latest_execution_resolution(execution_id)
        previous = self.state.get_latest_attestation_metadata(execution_id)
        attestation = issue_execution_attestation(
            execution,
            attestation_signer,
            policy_digest=execution.policy_digest,
            resolution=resolution,
            previous_attestation_digest=(previous.payload_digest if previous is not None else None),
        )
        metadata = attestation_metadata(attestation)
        try:
            self.state.record_attestation_metadata(metadata)
        except RuntimeError as exc:
            if str(exc).startswith("attestation."):
                raise ExecutionGuardError(str(exc)) from exc
            raise
        self.state.append(
            AuditEvent(
                event_id="evt_" + uuid4().hex,
                event_type=AuditEventType.EXECUTION_ATTESTATION_ISSUED,
                timestamp=attestation.payload.issued_at,
                trace_id=execution.trace_id,
                request_id=execution.request_id,
                decision_id=execution.decision_id,
                execution_id=execution.execution_id,
                source="agentguard",
                data={
                    "attestation_id": metadata.attestation_id,
                    "payload_digest": metadata.payload_digest,
                    "signer_key_id": metadata.signer_key_id,
                },
            )
        )
        return attestation

    def authorize(
        self,
        intent: ActionIntent,
        policy: PolicyDocument,
        *,
        mode: EnforcementMode = EnforcementMode.ENFORCE,
        ttl_seconds: int = 60,
    ) -> DecisionReceipt:
        self.state.append(self._event(AuditEventType.AUTHORIZATION_REQUESTED, intent))
        self._validate_intent_authority(intent)
        evaluation = evaluate_policy(policy, intent)
        needs_field_integrity = bool(intent.field_provenance or intent.field_releases) or any(
            rule.field_integrity for rule in evaluation.matched_rules
        )
        field_binding: FieldIntegrityBinding | None = None
        if needs_field_integrity:
            if self.provenance_verifier is None or self.release_verifier is None:
                raise ExecutionGuardError("field_integrity.verifier_unavailable")
            try:
                field_binding = validate_field_integrity(
                    intent,
                    evaluation.matched_rules,
                    self.provenance_verifier,
                    self.release_verifier,
                )
            except FieldIntegrityError as exc:
                raise ExecutionGuardError(str(exc)) from exc
        causal_required = bool(intent.causal_parent_execution_ids) or any(
            rule.causal is not None for rule in evaluation.matched_rules
        )
        causal_digest: str | None = None
        causal_depth: int | None = None
        if causal_required:
            causal_field_binding = field_binding or FieldIntegrityBinding(
                integrity_digest=digest({"constraints": [], "statements": []}),
                release_set_digest=digest([]),
                expires_at=None,
                release_ids=(),
                labels=frozenset(),
            )
            try:
                causal_digest, computed_depth, _ = validate_causal_context(
                    intent, evaluation.matched_rules, self.state, causal_field_binding
                )
            except CausalIntegrityError as exc:
                raise ExecutionGuardError(str(exc)) from exc
            causal_depth = computed_depth
        receipt = issue_decision_receipt(
            intent,
            evaluation,
            self.signer,
            ttl_seconds=ttl_seconds,
            mode=mode,
            field_binding=field_binding,
            causal_digest=causal_digest,
            causal_depth=causal_depth,
        )
        self.state.append(
            self._event(
                AuditEventType.AUTHORIZATION_DECIDED,
                intent,
                decision_id=receipt.decision_id,
                reason_code=receipt.reason_codes[0],
                data={"effect": receipt.effect.value, "policy_digest": receipt.policy_digest},
            )
        )
        return receipt

    def approve(
        self,
        intent: ActionIntent,
        receipt: DecisionReceipt,
        *,
        approver_subject: str,
        reason: str,
        authentication_level: str | None = None,
        maximum_uses: int = 1,
    ) -> ApprovalReceipt:
        approval = issue_approval_receipt(
            receipt,
            intent,
            self.signer,
            self.verifier,
            approver_subject=approver_subject,
            reason=reason,
            authentication_level=authentication_level,
            maximum_uses=maximum_uses,
        )
        self.state.register_approval(approval)
        self.state.append(
            self._event(
                AuditEventType.APPROVAL_GRANTED,
                intent,
                decision_id=receipt.decision_id,
                approval_id=approval.approval_id,
                data={"approver": approver_subject},
            )
        )
        return approval

    def request_credential(
        self,
        intent: ActionIntent,
        receipt: DecisionReceipt,
        request: CredentialRequest,
        broker: CredentialBroker,
        approval: ApprovalReceipt | None = None,
    ) -> CredentialGrant:
        """Retained broker/demo API; not the production protected-execution credential surface."""

        try:
            verify_decision_receipt(receipt, self.verifier)
            verify_intent_binding(intent, receipt)
        except ReceiptVerificationError as exc:
            raise CredentialVerificationError(str(exc)) from exc
        if approval is not None:
            verify_approval_receipt(approval, receipt, intent, self.verifier)
            if request.approval_id != approval.approval_id:
                raise ValueError("credential.approval_binding_mismatch")
        validate_credential_request(
            receipt,
            request,
            approval_verified=approval is not None,
        )
        ceiling = receipt.credential_ceiling
        assert ceiling is not None
        claim_error = self.state.claim_credential_issuance(
            request_id=request.request_id,
            decision_id=receipt.decision_id,
            approval_id=approval.approval_id if approval is not None else None,
            single_use=ceiling.single_use,
            claimed_at=datetime.now(UTC),
        )
        if claim_error is not None:
            raise CredentialVerificationError(claim_error)
        self.state.append(
            self._event(
                AuditEventType.CREDENTIAL_REQUESTED,
                intent,
                decision_id=receipt.decision_id,
                data={"audience": request.audience, "scope_count": len(request.scopes)},
            )
        )
        try:
            grant = broker.issue(receipt, request, approval)
            verify_credential_grant(receipt, grant, self.broker_grant_verifier)
        except Exception:
            self.state.finish_credential_issuance(
                request.request_id,
                None,
                succeeded=False,
                completed_at=datetime.now(UTC),
            )
            raise
        self.state.finish_credential_issuance(
            request.request_id,
            grant.issuance_id,
            succeeded=True,
            completed_at=datetime.now(UTC),
        )
        self.state.append(
            self._event(
                AuditEventType.CREDENTIAL_ISSUED,
                intent,
                decision_id=receipt.decision_id,
                issuance_id=grant.issuance_id,
                data={
                    "broker": grant.broker,
                    "audience": grant.audience,
                    "scope_count": len(grant.scopes),
                },
            )
        )
        return grant

    def guard_execution(
        self,
        intent: ActionIntent,
        receipt: DecisionReceipt,
        grant: CredentialGrant | None,
        approval: ApprovalReceipt | None = None,
        *,
        current_policy: PolicyDocument | None = None,
    ) -> None:
        """Compatibility preflight. This validates but never consumes execution authority."""

        authorize_execution(
            intent,
            receipt,
            grant,
            self.verifier,
            self.state,
            broker_grant_verifier=self.broker_grant_verifier,
            approval=approval,
            current_policy=current_policy,
            provenance_verifier=self.provenance_verifier,
            release_verifier=self.release_verifier,
            execution_repository=self.state,
        )

    def execute_protected(
        self,
        intent: ActionIntent,
        receipt: DecisionReceipt,
        grant: CredentialGrant | None,
        executor: ProtectedExecutor,
        approval: ApprovalReceipt | None = None,
        *,
        current_policy: PolicyDocument | None = None,
    ) -> ExecutionOutcome:
        """Own validation, one-winner reservation, controlled dispatch, and durable outcome."""

        if receipt.staging_requirement is not None and receipt.staging_requirement.required:
            raise ExecutionGuardError("execution.staging_required")
        execution_id = "exec_" + uuid4().hex
        self._validate_intent_authority(intent)
        verified = validate_execution_authority(
            intent,
            receipt,
            grant,
            self.verifier,
            execution_id=execution_id,
            broker_grant_verifier=self.broker_grant_verifier,
            approval=approval,
            current_policy=current_policy,
            provenance_verifier=self.provenance_verifier,
            release_verifier=self.release_verifier,
            execution_repository=self.state,
        )
        reserved_at = datetime.now(UTC)
        reservation_error = self.state.reserve_execution(verified, reserved_at)
        if reservation_error is not None:
            raise ExecutionGuardError(reservation_error)

        # The execution table is authoritative. Audit remains a separate hash-chain transaction;
        # failure here leaves a resumable RESERVED record and never triggers redispatch.
        self._append_consumption_events(intent, receipt, verified)
        return self._dispatch_reserved(verified, executor)

    def prepare_protected_execution(
        self,
        intent: ActionIntent,
        receipt: DecisionReceipt,
        grant: CredentialGrant | None,
        approval: ApprovalReceipt | None = None,
        *,
        current_policy: PolicyDocument | None = None,
    ) -> PreparedExecution:
        requirement = receipt.staging_requirement
        if requirement is None or not requirement.required:
            raise ExecutionGuardError("execution.staging_not_required")
        prepared_id = "prep_" + uuid4().hex
        execution_id = "exec_" + uuid4().hex
        self._validate_intent_authority(intent)
        verified = validate_execution_authority(
            intent,
            receipt,
            grant,
            self.verifier,
            execution_id=execution_id,
            broker_grant_verifier=self.broker_grant_verifier,
            approval=approval,
            current_policy=current_policy,
            provenance_verifier=self.provenance_verifier,
            release_verifier=self.release_verifier,
            execution_repository=self.state,
            prepared_id=prepared_id,
        )
        prepared_at = datetime.now(UTC)
        expires_at = min(
            prepared_at + timedelta(seconds=requirement.maximum_commit_window_seconds),
            verified.authorization_expires_at,
            *(
                [verified.field_integrity_expires_at]
                if verified.field_integrity_expires_at is not None
                else []
            ),
        )
        commit_not_before = prepared_at + timedelta(seconds=requirement.minimum_delay_seconds)
        if commit_not_before >= expires_at:
            raise ExecutionGuardError("execution.staging_window_invalid")
        prepared = PreparedExecution(
            prepared_id=prepared_id,
            execution_id=execution_id,
            decision_id=receipt.decision_id,
            request_id=intent.request_id,
            trace_id=intent.trace_id,
            intent_digest=verified.intent_digest,
            prepared_binding_digest=prepared_execution_binding_digest(verified),
            field_integrity_digest=verified.field_integrity_digest,
            causal_digest=verified.causal_digest,
            status=PreparedExecutionStatus.PREPARED,
            reversibility=requirement.reversibility,
            prepared_at=prepared_at,
            commit_not_before=commit_not_before,
            expires_at=expires_at,
        )
        self.state.store_prepared_execution(prepared)
        self.state.append(
            self._event(
                AuditEventType.EXECUTION_PREPARED,
                intent,
                decision_id=receipt.decision_id,
                execution_id=execution_id,
                data={
                    "prepared_id": prepared_id,
                    "reversibility": requirement.reversibility.value,
                    "prepared_binding_digest": prepared.prepared_binding_digest,
                },
            )
        )
        return prepared

    def cancel_prepared_execution(self, prepared_id: str) -> PreparedExecution:
        cancelled_at = datetime.now(UTC)
        try:
            prepared = self.state.cancel_prepared_execution(prepared_id, cancelled_at)
        except RuntimeError as exc:
            raise ExecutionGuardError(str(exc)) from exc
        self.state.append(
            AuditEvent(
                event_id="evt_" + uuid4().hex,
                event_type=AuditEventType.EXECUTION_PREPARE_CANCELLED,
                timestamp=cancelled_at,
                trace_id=prepared.trace_id,
                request_id=prepared.request_id,
                decision_id=prepared.decision_id,
                execution_id=prepared.execution_id,
                source="agentguard",
                data={"prepared_id": prepared.prepared_id},
            )
        )
        return prepared

    def commit_prepared_execution(
        self,
        prepared_id: str,
        intent: ActionIntent,
        receipt: DecisionReceipt,
        grant: CredentialGrant | None,
        executor: ProtectedExecutor,
        approval: ApprovalReceipt | None = None,
        *,
        current_policy: PolicyDocument | None = None,
    ) -> ExecutionOutcome:
        prepared = self.state.get_prepared_execution(prepared_id)
        if prepared is None:
            raise ExecutionGuardError("execution.prepared_missing")
        requirement = receipt.staging_requirement
        if requirement is None or not requirement.required:
            raise ExecutionGuardError("execution.staging_binding_missing")
        if requirement.require_fresh_approval:
            if approval is None or approval.issued_at < prepared.prepared_at:
                raise ExecutionGuardError("execution.fresh_approval_required")
        self._validate_intent_authority(intent)
        verified = validate_execution_authority(
            intent,
            receipt,
            grant,
            self.verifier,
            execution_id=prepared.execution_id,
            broker_grant_verifier=self.broker_grant_verifier,
            approval=approval,
            current_policy=current_policy,
            provenance_verifier=self.provenance_verifier,
            release_verifier=self.release_verifier,
            execution_repository=self.state,
            prepared_id=prepared_id,
        )
        reserved_at = datetime.now(UTC)
        reservation_error = self.state.reserve_prepared_execution(
            prepared_id, verified, reserved_at
        )
        if reservation_error is not None:
            raise ExecutionGuardError(reservation_error)
        self.state.append(
            self._event(
                AuditEventType.EXECUTION_COMMITTED,
                intent,
                decision_id=receipt.decision_id,
                execution_id=verified.execution_id,
                data={
                    "prepared_id": prepared_id,
                    "authority_digest": execution_authority_digest(verified),
                },
            )
        )
        self._append_consumption_events(intent, receipt, verified)
        return self._dispatch_reserved(verified, executor)

    def _append_consumption_events(
        self, intent: ActionIntent, receipt: DecisionReceipt, verified: VerifiedExecution
    ) -> None:
        self.state.append(
            self._event(
                AuditEventType.RECEIPT_CONSUMED,
                intent,
                decision_id=receipt.decision_id,
                execution_id=verified.execution_id,
                data={
                    "intent_digest": verified.intent_digest,
                    "authority_digest": execution_authority_digest(verified),
                    "state": ExecutionState.RESERVED.value,
                },
            )
        )
        if verified.authority_lease_id is not None:
            self.state.append(
                self._event(
                    AuditEventType.CAPABILITY_LEASE_CONSUMED,
                    intent,
                    decision_id=receipt.decision_id,
                    execution_id=verified.execution_id,
                    data={
                        "lease_id": verified.authority_lease_id,
                        "grant_id": verified.authority_grant_id,
                    },
                )
            )
        for release_id in verified.field_release_ids:
            self.state.append(
                self._event(
                    AuditEventType.FIELD_RELEASE_CONSUMED,
                    intent,
                    decision_id=receipt.decision_id,
                    execution_id=verified.execution_id,
                    data={"release_id": release_id},
                )
            )
        if intent.causal_parent_execution_ids:
            self.state.append(
                self._event(
                    AuditEventType.CAUSAL_CONTEXT_BOUND,
                    intent,
                    decision_id=receipt.decision_id,
                    execution_id=verified.execution_id,
                    data={
                        "parent_count": len(intent.causal_parent_execution_ids),
                        "causal_digest": verified.causal_digest,
                        "causal_depth": verified.causal_depth,
                    },
                )
            )

    def resume_reserved_execution(
        self,
        execution_id: str,
        intent: ActionIntent,
        receipt: DecisionReceipt,
        grant: CredentialGrant | None,
        executor: ProtectedExecutor,
        approval: ApprovalReceipt | None = None,
        *,
        current_policy: PolicyDocument | None = None,
    ) -> ExecutionOutcome:
        """Explicitly resume a known-safe RESERVED execution after full authority revalidation."""

        record = self.state.get_execution(execution_id)
        if record is None:
            raise ExecutionGuardError("execution.record_missing")
        if record.state != ExecutionState.RESERVED:
            raise ExecutionGuardError("execution.not_reserved")
        self._validate_intent_authority(intent, allow_consumed_lease=True)
        verified = validate_execution_authority(
            intent,
            receipt,
            grant,
            self.verifier,
            execution_id=execution_id,
            broker_grant_verifier=self.broker_grant_verifier,
            approval=approval,
            current_policy=current_policy,
            provenance_verifier=self.provenance_verifier,
            release_verifier=self.release_verifier,
            execution_repository=self.state,
            prepared_id=record.prepared_id,
        )
        if record.authority_digest != execution_authority_digest(verified):
            raise ExecutionGuardError("execution.reserved_binding_mismatch")
        return self._dispatch_reserved(verified, executor)

    def _dispatch_reserved(
        self,
        verified: VerifiedExecution,
        executor: ProtectedExecutor,
    ) -> ExecutionOutcome:
        try:
            # The state adapter owns final dispatch admission: it serializes the RESERVED ->
            # DISPATCHING transition, samples fresh time after acquiring the write lock, and
            # revalidates the exact reserved authority before any executor invocation.
            dispatching_at = self.state.mark_execution_dispatching(verified)
        except RuntimeError as exc:
            raise ExecutionGuardError(str(exc)) from exc

        try:
            result = executor.execute(verified)
        except DefiniteExecutionFailure as exc:
            result = ProtectedExecutionResult(
                status=ExecutionStatus.FAILURE,
                provider_status=exc.provider_status,
                result_digest=exc.result_digest,
                error_code=exc.error_code,
            )
        except AmbiguousExecutionError as exc:
            result = ProtectedExecutionResult(
                status=ExecutionStatus.UNKNOWN,
                error_code=exc.error_code,
            )
        except Exception:
            result = ProtectedExecutionResult(
                status=ExecutionStatus.UNKNOWN,
                error_code="execution.executor_exception",
            )

        terminal_state = {
            ExecutionStatus.SUCCESS: ExecutionState.SUCCEEDED,
            ExecutionStatus.FAILURE: ExecutionState.FAILED,
            ExecutionStatus.UNKNOWN: ExecutionState.UNKNOWN,
        }[result.status]
        completed_at = datetime.now(UTC)
        try:
            self.state.finish_execution(
                verified.execution_id,
                terminal_state,
                completed_at=completed_at,
                provider_status=result.provider_status,
                result_digest=result.result_digest,
                error_code=result.error_code,
            )
        except Exception as exc:
            # The durable state remains DISPATCHING. Recovery must conservatively classify it
            # UNKNOWN rather than claiming a provider result that was not persisted.
            raise ExecutionPersistenceError("execution.terminal_persistence_failed") from exc

        outcome = ExecutionOutcome(
            execution_id=verified.execution_id,
            trace_id=verified.trace_id,
            decision_id=verified.decision_id,
            status=result.status,
            provider_status=result.provider_status,
            result_digest=result.result_digest,
            error_code=result.error_code,
            started_at=dispatching_at,
            completed_at=completed_at,
        )

        # Hash-chained audit is intentionally written after the authoritative terminal state.
        # This avoids allowing an audit failure to trigger an external dispatch retry. The audit
        # and execution-state transactions are not atomic; Phase 5A reports this residual gap.
        self.state.append(
            self._event(
                AuditEventType.EXECUTION_STARTED,
                verified.intent,
                timestamp=dispatching_at,
                decision_id=verified.decision_id,
                execution_id=verified.execution_id,
                data={
                    "intent_digest": verified.intent_digest,
                    "authority_digest": execution_authority_digest(verified),
                },
            )
        )
        terminal_event = {
            ExecutionStatus.SUCCESS: AuditEventType.EXECUTION_SUCCEEDED,
            ExecutionStatus.FAILURE: AuditEventType.EXECUTION_FAILED,
            ExecutionStatus.UNKNOWN: AuditEventType.EXECUTION_UNKNOWN,
        }[result.status]
        self.state.append(
            self._event(
                terminal_event,
                verified.intent,
                timestamp=completed_at,
                decision_id=verified.decision_id,
                execution_id=verified.execution_id,
                reason_code=result.error_code,
                data={
                    "intent_digest": verified.intent_digest,
                    "authority_digest": execution_authority_digest(verified),
                    "provider_status": result.provider_status,
                    "result_digest": result.result_digest,
                },
            )
        )
        return outcome

    def recover_incomplete_executions(self) -> tuple[ExecutionRecord, ...]:
        """Terminalize stranded DISPATCHING records as UNKNOWN without re-dispatching."""

        recovered_at = datetime.now(UTC)
        recovered = self.state.recover_incomplete_executions(recovered_at)
        for record in recovered:
            self.state.append(
                AuditEvent(
                    event_id="evt_" + uuid4().hex,
                    event_type=AuditEventType.EXECUTION_UNKNOWN,
                    timestamp=recovered_at,
                    trace_id=record.trace_id,
                    request_id=record.request_id,
                    decision_id=record.decision_id,
                    execution_id=record.execution_id,
                    source="agentguard",
                    reason_code=record.error_code,
                    data={
                        "intent_digest": record.intent_digest,
                        "authority_digest": record.authority_digest,
                        "recovered": True,
                    },
                )
            )
        return recovered
