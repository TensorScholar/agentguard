from __future__ import annotations

import pytest

from agentguard.adapters.broker import MockCredentialBroker
from agentguard.application import AgentGuardService
from agentguard.domain import CredentialCeiling, CredentialRequest, Effect
from agentguard.domain.policy import ActionMatcher, PolicyRule
from agentguard.engine.execution import ExecutionGuardError
from agentguard.engine.receipts import ReceiptVerificationError, verify_approval_receipt


def approval_policy(policy):
    rule = PolicyRule(
        id="approved-refund",
        priority=2000,
        effect=Effect.REQUIRE_APPROVAL,
        action=ActionMatcher(tools=frozenset({"refund.create"})),
        credential=CredentialCeiling(
            audience="payments.internal",
            scopes=frozenset({"refund:create"}),
            maximum_ttl_seconds=60,
            tenant_id="acme",
        ),
        execution_budget=policy.rules[1].execution_budget,
        reason_code="approval.refund_required",
    )
    return policy.model_copy(update={"rules": (rule,)})


def test_signed_approval_enables_broker_and_execution(intent, policy, signer, verifier, state):
    service = AgentGuardService(signer, verifier, state)
    receipt = service.authorize(intent, approval_policy(policy))
    assert receipt.effect == Effect.REQUIRE_APPROVAL
    approval = service.approve(
        intent,
        receipt,
        approver_subject="security@example.com",
        reason="Reviewed customer escalation",
        authentication_level="mfa",
    )
    ceiling = receipt.credential_ceiling
    request = CredentialRequest(
        request_id="cred-approved",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=30,
        tenant_id=ceiling.tenant_id,
        approval_id=approval.approval_id,
    )
    grant = service.request_credential(intent, receipt, request, MockCredentialBroker(), approval)
    service.guard_execution(intent, receipt, grant, approval)
    assert state.verify()[0]


def test_missing_approval_is_rejected(intent, policy, signer, verifier, state):
    service = AgentGuardService(signer, verifier, state)
    receipt = service.authorize(intent, approval_policy(policy))
    with pytest.raises(ExecutionGuardError, match="approval_missing"):
        service.guard_execution(intent, receipt, None)


def test_approval_argument_substitution_rejected(intent, policy, signer, verifier, state):
    service = AgentGuardService(signer, verifier, state)
    receipt = service.authorize(intent, approval_policy(policy))
    approval = service.approve(intent, receipt, approver_subject="security", reason="approved")
    changed = intent.model_copy(update={"arguments": {**intent.arguments, "amount_minor": 9999}})
    with pytest.raises(ReceiptVerificationError, match="arguments_digest_mismatch"):
        verify_approval_receipt(approval, receipt, changed, verifier)


def test_tampered_approval_rejected(intent, policy, signer, verifier, state):
    service = AgentGuardService(signer, verifier, state)
    receipt = service.authorize(intent, approval_policy(policy))
    approval = service.approve(intent, receipt, approver_subject="security", reason="approved")
    tampered = approval.model_copy(update={"reason": "changed"})
    with pytest.raises(ReceiptVerificationError, match="signature_invalid"):
        verify_approval_receipt(tampered, receipt, intent, verifier)


def test_approval_binding_required_for_credential(intent, policy, signer, verifier, state):
    service = AgentGuardService(signer, verifier, state)
    receipt = service.authorize(intent, approval_policy(policy))
    approval = service.approve(intent, receipt, approver_subject="security", reason="approved")
    ceiling = receipt.credential_ceiling
    request = CredentialRequest(
        request_id="cred-bad-binding",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=30,
        tenant_id=ceiling.tenant_id,
        approval_id="wrong",
    )
    with pytest.raises(ValueError, match="approval_binding_mismatch"):
        service.request_credential(intent, receipt, request, MockCredentialBroker(), approval)
