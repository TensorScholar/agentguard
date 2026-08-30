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
    FieldIntegrityBinding,
    PolicyDocument,
    VerifiedCredentialAuthority,
    VerifiedExecution,
)
from agentguard.engine.canonical import digest
from agentguard.engine.causal import CausalIntegrityError, validate_causal_context
from agentguard.engine.credentials import CredentialVerificationError, verify_credential_grant
from agentguard.engine.field_integrity import FieldIntegrityError, validate_field_integrity
from agentguard.engine.policy import evaluate_policy
from agentguard.engine.receipts import (
    ReceiptVerificationError,
    verify_approval_receipt,
    verify_decision_receipt,
    verify_intent_binding,
)
from agentguard.ports import (
    BrokerGrantVerifier,
    ExecutionRepository,
    NonceRepository,
    SignatureVerifier,
)


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


def _execution_binding_payload(
    verified: VerifiedExecution, *, include_approval: bool
) -> dict[str, object]:
    payload: dict[str, object] = {
        "execution_id": verified.execution_id,
        "decision_id": verified.decision_id,
        "request_id": verified.request_id,
        "trace_id": verified.trace_id,
        "intent_digest": verified.intent_digest,
        "policy_digest": verified.policy_digest,
        "nonce_digest": digest(verified.nonce),
        "authority_grant_id": verified.authority_grant_id,
        "authority_lease_id": verified.authority_lease_id,
        "authority_chain_digest": verified.authority_chain_digest,
        "field_integrity_digest": verified.field_integrity_digest,
        "field_release_set_digest": verified.field_release_set_digest,
        "field_integrity_expires_at": verified.field_integrity_expires_at,
        "causal_digest": verified.causal_digest,
        "causal_depth": verified.causal_depth,
        "causal_labels": verified.causal_labels,
        "causal_parent_execution_ids": verified.causal_parent_execution_ids,
        "prepared_id": verified.prepared_id,
        "credential_authority": verified.credential_authority,
        "authorization_expires_at": verified.authorization_expires_at,
    }
    if include_approval:
        payload["approval_id"] = verified.approval_id
    return payload


def execution_authority_digest(verified: VerifiedExecution) -> str:
    """Digest the exact final execution authority, including the approval actually consumed."""

    return digest(_execution_binding_payload(verified, include_approval=True))


def prepared_execution_binding_digest(verified: VerifiedExecution) -> str:
    """Bind an immutable staged action while permitting a required fresh commit approval.

    The final execution authority digest still binds the approval actually used at commit.
    This staged binding intentionally excludes only ``approval_id``; all other execution,
    delegated-authority, field-integrity, causal, credential, nonce, and expiry bindings remain exact.
    """

    return digest(_execution_binding_payload(verified, include_approval=False))


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
    provenance_verifier: SignatureVerifier | None = None,
    release_verifier: SignatureVerifier | None = None,
    execution_repository: ExecutionRepository | None = None,
    prepared_id: str | None = None,
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
    evaluation = evaluate_policy(current_policy, intent, now=now)
    if (
        evaluation.effect != receipt.effect
        or tuple(rule.id for rule in evaluation.matched_rules) != receipt.matched_rule_ids
        or evaluation.staging_requirement != receipt.staging_requirement
    ):
        raise ExecutionGuardError("execution.policy_revalidation_mismatch")

    needs_field_integrity = bool(intent.field_provenance or intent.field_releases) or any(
        rule.field_integrity for rule in evaluation.matched_rules
    )
    if needs_field_integrity:
        if provenance_verifier is None or release_verifier is None:
            raise ExecutionGuardError("field_integrity.verifier_unavailable")
        try:
            field_binding = validate_field_integrity(
                intent,
                evaluation.matched_rules,
                provenance_verifier,
                release_verifier,
                now=now,
            )
        except FieldIntegrityError as exc:
            raise ExecutionGuardError(str(exc)) from exc
    else:
        field_binding = FieldIntegrityBinding(
            integrity_digest=digest({"constraints": [], "statements": []}),
            release_set_digest=digest([]),
            expires_at=None,
            release_ids=(),
            labels=frozenset(),
        )
    expected_field_digest = receipt.field_integrity_digest
    if expected_field_digest != (field_binding.integrity_digest if needs_field_integrity else None):
        raise ExecutionGuardError("field_integrity.receipt_binding_mismatch")
    expected_release_digest = receipt.field_release_set_digest
    if expected_release_digest != (
        field_binding.release_set_digest if needs_field_integrity else None
    ):
        raise ExecutionGuardError("field_integrity.release_binding_mismatch")
    if receipt.field_integrity_expires_at != (
        field_binding.expires_at if needs_field_integrity else None
    ):
        raise ExecutionGuardError("field_integrity.expiry_binding_mismatch")

    causal_required = bool(intent.causal_parent_execution_ids) or any(
        rule.causal is not None for rule in evaluation.matched_rules
    )
    if causal_required:
        if execution_repository is None:
            raise ExecutionGuardError("causal.repository_unavailable")
        try:
            causal_digest, causal_depth, causal_labels = validate_causal_context(
                intent, evaluation.matched_rules, execution_repository, field_binding
            )
        except CausalIntegrityError as exc:
            raise ExecutionGuardError(str(exc)) from exc
    else:
        causal_digest = digest(
            {
                "parents": [],
                "depth": 0,
                "labels": field_binding.labels,
                "tenant_id": intent.principal.tenant_id,
                "request_id": intent.request_id,
            }
        )
        causal_depth = 0
        causal_labels = field_binding.labels
    if receipt.causal_digest != (causal_digest if causal_required else None):
        raise ExecutionGuardError("causal.receipt_binding_mismatch")
    if receipt.causal_depth != (causal_depth if causal_required else None):
        raise ExecutionGuardError("causal.depth_binding_mismatch")
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
        authority_grant_id=(intent.authority.grant_id if intent.authority is not None else None),
        authority_lease_id=(intent.authority.lease_id if intent.authority is not None else None),
        authority_chain_digest=(
            intent.authority.chain_digest if intent.authority is not None else None
        ),
        field_integrity_digest=(field_binding.integrity_digest if needs_field_integrity else None),
        field_release_set_digest=(
            field_binding.release_set_digest if needs_field_integrity else None
        ),
        field_integrity_expires_at=(field_binding.expires_at if needs_field_integrity else None),
        field_release_ids=(field_binding.release_ids if needs_field_integrity else ()),
        causal_digest=causal_digest,
        causal_depth=causal_depth,
        causal_labels=causal_labels,
        causal_parent_execution_ids=tuple(intent.causal_parent_execution_ids),
        prepared_id=prepared_id,
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
    provenance_verifier: SignatureVerifier | None = None,
    release_verifier: SignatureVerifier | None = None,
    execution_repository: ExecutionRepository | None = None,
    now: datetime | None = None,
) -> None:
    """Compatibility preflight for v0.2 callers.

    Historically this function consumed the decision nonce. It is intentionally non-consuming now;
    only the protected execution lifecycle may claim execution authority through
    reserve_execution().
    The nonce_repository argument remains accepted so existing call sites do not break abruptly.
    """

    if (
        execution_repository is None
        and nonce_repository is not None
        and hasattr(nonce_repository, "get_execution")
    ):
        execution_repository = nonce_repository  # type: ignore[assignment]
    validate_execution_authority(
        intent,
        receipt,
        grant,
        verifier,
        execution_id="preflight_" + uuid4().hex,
        broker_grant_verifier=broker_grant_verifier,
        approval=approval,
        current_policy=current_policy,
        provenance_verifier=provenance_verifier,
        release_verifier=release_verifier,
        execution_repository=execution_repository,
        now=now,
    )
