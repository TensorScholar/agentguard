from __future__ import annotations

from datetime import UTC, datetime
from typing import Any
from uuid import uuid4

from agentguard.domain import (
    ActionIntent,
    ApprovalReceipt,
    AuditEvent,
    AuditEventType,
    CredentialGrant,
    CredentialRequest,
    DecisionReceipt,
    EnforcementMode,
    ExecutionOutcome,
    ExecutionRecord,
    ExecutionState,
    ExecutionStatus,
    PolicyDocument,
    ProtectedExecutionResult,
    VerifiedExecution,
)
from agentguard.engine.credentials import (
    CredentialVerificationError,
    validate_credential_request,
    verify_credential_grant,
)
from agentguard.engine.execution import (
    ExecutionGuardError,
    authorize_execution,
    execution_authority_digest,
    validate_execution_authority,
)
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
    ) -> None:
        self.signer = signer
        self.verifier = verifier
        self.state = state
        self.broker_grant_verifier = broker_grant_verifier

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

    def authorize(
        self,
        intent: ActionIntent,
        policy: PolicyDocument,
        *,
        mode: EnforcementMode = EnforcementMode.ENFORCE,
        ttl_seconds: int = 60,
    ) -> DecisionReceipt:
        self.state.append(self._event(AuditEventType.AUTHORIZATION_REQUESTED, intent))
        evaluation = evaluate_policy(policy, intent)
        receipt = issue_decision_receipt(
            intent, evaluation, self.signer, ttl_seconds=ttl_seconds, mode=mode
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

        execution_id = "exec_" + uuid4().hex
        verified = validate_execution_authority(
            intent,
            receipt,
            grant,
            self.verifier,
            execution_id=execution_id,
            broker_grant_verifier=self.broker_grant_verifier,
            approval=approval,
            current_policy=current_policy,
        )
        reserved_at = datetime.now(UTC)
        reservation_error = self.state.reserve_execution(verified, reserved_at)
        if reservation_error is not None:
            raise ExecutionGuardError(reservation_error)

        # The execution table is authoritative. Audit append remains a separate hash-chain
        # transaction; failure here leaves a resumable RESERVED record and never dispatches.
        self.state.append(
            self._event(
                AuditEventType.RECEIPT_CONSUMED,
                intent,
                decision_id=receipt.decision_id,
                execution_id=execution_id,
                data={
                    "intent_digest": verified.intent_digest,
                    "authority_digest": execution_authority_digest(verified),
                    "state": ExecutionState.RESERVED.value,
                },
            )
        )
        return self._dispatch_reserved(verified, executor)

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
        verified = validate_execution_authority(
            intent,
            receipt,
            grant,
            self.verifier,
            execution_id=execution_id,
            broker_grant_verifier=self.broker_grant_verifier,
            approval=approval,
            current_policy=current_policy,
        )
        if record.authority_digest != execution_authority_digest(verified):
            raise ExecutionGuardError("execution.reserved_binding_mismatch")
        return self._dispatch_reserved(verified, executor)

    def _dispatch_reserved(
        self,
        verified: VerifiedExecution,
        executor: ProtectedExecutor,
    ) -> ExecutionOutcome:
        dispatching_at = datetime.now(UTC)
        try:
            self.state.mark_execution_dispatching(verified.execution_id, dispatching_at)
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
