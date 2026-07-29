from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any
from uuid import uuid4

from agentguard.adapters.crypto import decode_signature, encode_signature
from agentguard.domain import (
    ActionIntent,
    ApprovalReceipt,
    DecisionReceipt,
    Effect,
    EnforcementMode,
    ExecutionBudget,
)
from agentguard.ports import SignatureVerifier, Signer

from .canonical import canonical_bytes, digest
from .policy import PolicyEvaluation


class ReceiptVerificationError(ValueError):
    pass


def _unsigned(receipt: DecisionReceipt) -> dict[str, Any]:
    data = receipt.model_dump(mode="python")
    data["signature"] = ""
    return data


def issue_decision_receipt(
    intent: ActionIntent,
    evaluation: PolicyEvaluation,
    signer: Signer,
    *,
    now: datetime | None = None,
    ttl_seconds: int = 60,
    mode: EnforcementMode = EnforcementMode.ENFORCE,
) -> DecisionReceipt:
    now = now or datetime.now(UTC)
    selected = evaluation.selected_rule
    ceiling = (
        selected.credential
        if selected and evaluation.effect in {Effect.ALLOW, Effect.REQUIRE_APPROVAL}
        else None
    )
    budget = selected.execution_budget if selected else ExecutionBudget()
    receipt = DecisionReceipt(
        decision_id="dec_" + uuid4().hex,
        request_id=intent.request_id,
        trace_id=intent.trace_id,
        effect=evaluation.effect,
        reason_codes=evaluation.reason_codes,
        matched_rule_ids=tuple(r.id for r in evaluation.matched_rules),
        intent_digest=digest(intent),
        principal_digest=digest(intent.principal),
        subject_digest=digest(intent.subject) if intent.subject else None,
        action_digest=digest(intent.action),
        resource_digest=digest(intent.resource) if intent.resource else None,
        arguments_digest=digest(intent.arguments),
        effects_digest=digest(intent.effects),
        tool_schema_digest=digest(intent.tool_schema),
        policy_digest=evaluation.policy_digest,
        credential_ceiling=ceiling,
        execution_budget=budget,
        enforcement_mode=mode,
        issued_at=now,
        not_before=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        nonce="nonce_" + uuid4().hex,
        key_id=signer.key_id,
        signature="",
    )
    sig = encode_signature(signer.sign(canonical_bytes(_unsigned(receipt))))
    return receipt.model_copy(update={"signature": sig})


def verify_decision_receipt(
    receipt: DecisionReceipt,
    verifier: SignatureVerifier,
    *,
    now: datetime | None = None,
    clock_skew_seconds: int = 5,
) -> None:
    now = now or datetime.now(UTC)
    try:
        signature = decode_signature(receipt.signature)
    except ValueError as exc:
        raise ReceiptVerificationError("receipt.signature_invalid") from exc
    if not verifier.verify(receipt.key_id, canonical_bytes(_unsigned(receipt)), signature):
        raise ReceiptVerificationError("receipt.signature_invalid")
    skew = timedelta(seconds=clock_skew_seconds)
    if now + skew < receipt.not_before:
        raise ReceiptVerificationError("receipt.not_yet_valid")
    if now - skew > receipt.expires_at:
        raise ReceiptVerificationError("receipt.expired")


def verify_intent_binding(intent: ActionIntent, receipt: DecisionReceipt) -> None:
    checks = {
        "principal": (digest(intent.principal), receipt.principal_digest),
        "subject": (digest(intent.subject) if intent.subject else None, receipt.subject_digest),
        "action": (digest(intent.action), receipt.action_digest),
        "resource": (digest(intent.resource) if intent.resource else None, receipt.resource_digest),
        "arguments": (digest(intent.arguments), receipt.arguments_digest),
        "effects": (digest(intent.effects), receipt.effects_digest),
        "tool_schema": (digest(intent.tool_schema), receipt.tool_schema_digest),
    }
    for name, (actual, expected) in checks.items():
        if actual != expected:
            raise ReceiptVerificationError(f"execution.{name}_digest_mismatch")
    if digest(intent) != receipt.intent_digest:
        raise ReceiptVerificationError("execution.intent_digest_mismatch")


def _unsigned_approval(receipt: ApprovalReceipt) -> dict[str, Any]:
    data = receipt.model_dump(mode="python")
    data["signature"] = ""
    return data


def issue_approval_receipt(
    decision_receipt: DecisionReceipt,
    intent: ActionIntent,
    signer: Signer,
    verifier: SignatureVerifier,
    *,
    approver_subject: str,
    reason: str,
    authentication_level: str | None = None,
    now: datetime | None = None,
    ttl_seconds: int = 300,
    approved_budget: ExecutionBudget | None = None,
) -> ApprovalReceipt:
    verify_decision_receipt(decision_receipt, verifier, now=now)
    if decision_receipt.effect != Effect.REQUIRE_APPROVAL:
        raise ReceiptVerificationError("approval.decision_not_pending")
    verify_intent_binding(intent, decision_receipt)
    now = now or datetime.now(UTC)
    approval = ApprovalReceipt(
        approval_id="apr_" + uuid4().hex,
        decision_id=decision_receipt.decision_id,
        trace_id=decision_receipt.trace_id,
        approver_subject=approver_subject,
        authentication_level=authentication_level,
        approved_action_digest=decision_receipt.action_digest,
        approved_resource_digest=decision_receipt.resource_digest,
        approved_arguments_digest=decision_receipt.arguments_digest,
        approved_budget=approved_budget or decision_receipt.execution_budget,
        reason=reason,
        maximum_uses=1,
        issued_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
        key_id=signer.key_id,
        signature="",
    )
    sig = encode_signature(signer.sign(canonical_bytes(_unsigned_approval(approval))))
    return approval.model_copy(update={"signature": sig})


def verify_approval_receipt(
    approval: ApprovalReceipt,
    decision_receipt: DecisionReceipt,
    intent: ActionIntent,
    verifier: SignatureVerifier,
    *,
    now: datetime | None = None,
) -> None:
    now = now or datetime.now(UTC)
    try:
        signature = decode_signature(approval.signature)
    except ValueError as exc:
        raise ReceiptVerificationError("approval.signature_invalid") from exc
    if not verifier.verify(
        approval.key_id,
        canonical_bytes(_unsigned_approval(approval)),
        signature,
    ):
        raise ReceiptVerificationError("approval.signature_invalid")
    if (
        approval.decision_id != decision_receipt.decision_id
        or approval.trace_id != decision_receipt.trace_id
    ):
        raise ReceiptVerificationError("approval.decision_binding_mismatch")
    if approval.expires_at < now:
        raise ReceiptVerificationError("approval.expired")
    if approval.maximum_uses != 1:
        raise ReceiptVerificationError("approval.multi_use_not_supported")
    if approval.approved_action_digest != digest(intent.action):
        raise ReceiptVerificationError("approval.action_digest_mismatch")
    if approval.approved_resource_digest != (digest(intent.resource) if intent.resource else None):
        raise ReceiptVerificationError("approval.resource_digest_mismatch")
    if approval.approved_arguments_digest != digest(intent.arguments):
        raise ReceiptVerificationError("approval.arguments_digest_mismatch")
