from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

from agentguard.domain import (
    ActionIntent,
    ApprovalReceipt,
    CredentialGrant,
    DecisionReceipt,
    Effect,
    ExecutionBudget,
    PolicyDocument,
    VerifiedCredentialAuthority,
    VerifiedExecution,
)
from agentguard.engine.canonical import digest
from agentguard.engine.credentials import CredentialVerificationError, verify_credential_grant
from agentguard.engine.receipts import (
    ReceiptVerificationError,
    verify_approval_receipt,
    verify_decision_receipt,
    verify_intent_binding,
)
from agentguard.ports import BrokerGrantVerifier, NonceRepository, SignatureVerifier


class ExecutionGuardError(ValueError):
    pass


def _check_budget(intent: ActionIntent, b: ExecutionBudget) -> None:
    pairs = [
        (
            "financial_amount",
            intent.effects.financial_amount_minor,
            b.maximum_financial_amount_minor,
        ),
        ("records_modified", intent.effects.records_modified, b.maximum_records_modified),
        ("external_recipients", intent.effects.external_recipients, b.maximum_external_recipients),
        ("deleted_files", intent.effects.deleted_files, b.maximum_deleted_files),
        ("tool_calls", intent.effects.tool_calls, b.maximum_tool_calls),
        ("execution_seconds", intent.effects.execution_seconds, b.maximum_execution_seconds),
        ("output_bytes", intent.effects.output_bytes, b.maximum_output_bytes),
    ]
    for name, value, maximum in pairs:
        if maximum is not None and (value is None or value > maximum):
            raise ExecutionGuardError(f"execution.budget.{name}_exceeded")


def _constrain_credential_authority(
    grant: CredentialGrant | None,
) -> VerifiedCredentialAuthority | None:
    if grant is None:
        return None
    return VerifiedCredentialAuthority(
        grant_id=grant.grant_id,
        issuance_id=grant.issuance_id,
        mode=grant.mode,
        credential_handle_digest=grant.credential_handle_digest,
        audience=grant.audience,
        scopes=grant.scopes,
        tenant_id=grant.tenant_id,
        expires_at=grant.expires_at,
        broker=grant.broker,
        broker_key_id=grant.broker_key_id,
    )


def execution_authority_digest(verified: VerifiedExecution) -> str:
    """Digest the trusted execution binding without persisting raw intent or credential material."""

    return digest(
        {
            "execution_id": verified.execution_id,
            "decision_id": verified.decision_id,
            "request_id": verified.request_id,
            "trace_id": verified.trace_id,
            "intent_digest": verified.intent_digest,
            "policy_digest": verified.policy_digest,
            "nonce_digest": digest(verified.nonce),
            "approval_id": verified.approval_id,
            "credential_authority": verified.credential_authority,
            "authorization_expires_at": verified.authorization_expires_at,
        }
    )


def validate_execution_authority(
    intent: ActionIntent,
    receipt: DecisionReceipt,
    grant: CredentialGrant | None,
    verifier: SignatureVerifier,
    *,
    execution_id: str,
    broker_grant_verifier: BrokerGrantVerifier | None = None,
    approval: ApprovalReceipt | None = None,
    current_policy: PolicyDocument | None = None,
    now: datetime | None = None,
) -> VerifiedExecution:
    """Validate execution authority without consuming the nonce or mutating lifecycle state."""

    now = now or datetime.now(UTC)
    try:
        verify_decision_receipt(receipt, verifier, now=now)
        verify_intent_binding(intent, receipt)
    except ReceiptVerificationError as exc:
        raise ExecutionGuardError(str(exc)) from exc
    if current_policy is None:
        raise ExecutionGuardError("execution.policy_unavailable")
    if digest(current_policy) != receipt.policy_digest:
        raise ExecutionGuardError("execution.policy_changed")
    if receipt.effect == Effect.DENY:
        raise ExecutionGuardError("execution.decision_not_allow")
    if receipt.effect == Effect.REQUIRE_APPROVAL:
        if approval is None:
            raise ExecutionGuardError("execution.approval_missing")
        try:
            verify_approval_receipt(approval, receipt, intent, verifier, now=now)
        except ReceiptVerificationError as exc:
            raise ExecutionGuardError(str(exc)) from exc
        _check_budget(intent, approval.approved_budget)
    elif approval is not None:
        raise ExecutionGuardError("execution.approval_unexpected")
    _check_budget(intent, receipt.execution_budget)
    if receipt.credential_ceiling is not None:
        if grant is None:
            raise ExecutionGuardError("execution.credential_missing")
        try:
            verify_credential_grant(receipt, grant, broker_grant_verifier, now=now)
        except CredentialVerificationError as exc:
            raise ExecutionGuardError(str(exc)) from exc
    elif grant is not None:
        raise ExecutionGuardError("execution.credential_unexpected")

    trusted_intent = intent.model_copy(deep=True)
    return VerifiedExecution(
        execution_id=execution_id,
        decision_id=receipt.decision_id,
        request_id=receipt.request_id,
        trace_id=receipt.trace_id,
        intent=trusted_intent,
        intent_digest=receipt.intent_digest,
        policy_digest=receipt.policy_digest,
        nonce=receipt.nonce,
        approval_id=approval.approval_id if approval is not None else None,
        credential_authority=_constrain_credential_authority(grant),
        authorization_expires_at=receipt.expires_at,
        verified_at=now,
    )


def authorize_execution(
    intent: ActionIntent,
    receipt: DecisionReceipt,
    grant: CredentialGrant | None,
    verifier: SignatureVerifier,
    nonce_repository: NonceRepository | None = None,
    *,
    broker_grant_verifier: BrokerGrantVerifier | None = None,
    approval: ApprovalReceipt | None = None,
    current_policy: PolicyDocument | None = None,
    now: datetime | None = None,
) -> None:
    """Compatibility preflight for v0.2 callers.

    Historically this function consumed the decision nonce. It is intentionally non-consuming now;
    only the protected execution lifecycle may claim execution authority through
    reserve_execution().
    The nonce_repository argument remains accepted so existing call sites do not break abruptly.
    """

    del nonce_repository
    validate_execution_authority(
        intent,
        receipt,
        grant,
        verifier,
        execution_id="preflight_" + uuid4().hex,
        broker_grant_verifier=broker_grant_verifier,
        approval=approval,
        current_policy=current_policy,
        now=now,
    )
