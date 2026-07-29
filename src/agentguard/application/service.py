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
    PolicyDocument,
)
from agentguard.engine.credentials import (
    CredentialVerificationError,
    validate_credential_request,
    verify_credential_grant,
)
from agentguard.engine.execution import authorize_execution
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
    BrokerGrantVerifier,
    CredentialBroker,
    SignatureVerifier,
    Signer,
    StateRepository,
)


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
        return AuditEvent(
            event_id="evt_" + uuid4().hex,
            event_type=event_type,
            timestamp=datetime.now(UTC),
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
        self.state.append(
            self._event(
                AuditEventType.RECEIPT_CONSUMED,
                intent,
                decision_id=receipt.decision_id,
                data={"nonce": receipt.nonce},
            )
        )
