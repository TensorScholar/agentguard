from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agentguard.adapters.crypto import Ed25519Signer
from agentguard.application import AgentGuardService
from agentguard.domain import CredentialRequest, Effect
from agentguard.engine.credentials import CredentialVerificationError
from agentguard.engine.policy import evaluate_policy
from agentguard.engine.receipts import (
    ReceiptVerificationError,
    issue_decision_receipt,
)


class BrokerSpy:
    def __init__(self) -> None:
        self.calls = 0

    def issue(self, receipt, request, approval=None):
        self.calls += 1
        raise AssertionError("broker must not be invoked")


def _request(receipt):
    ceiling = receipt.credential_ceiling
    assert ceiling is not None
    return CredentialRequest(
        request_id="cred-adversarial",
        trace_id=receipt.trace_id,
        decision_id=receipt.decision_id,
        audience=ceiling.audience,
        scopes=ceiling.scopes,
        requested_ttl_seconds=30,
        tenant_id=ceiling.tenant_id,
    )


@pytest.mark.parametrize(
    "mutation",
    [
        lambda receipt: receipt.model_copy(update={"signature": "invalid"}),
        lambda receipt: receipt.model_copy(update={"key_id": "unknown-key"}),
        lambda receipt: receipt.model_copy(update={"effect": Effect.REQUIRE_APPROVAL}),
    ],
)
def test_credential_entrypoint_rejects_untrusted_receipts_without_broker_call(
    intent, policy, signer, verifier, state, mutation
):
    service = AgentGuardService(signer, verifier, state)
    trusted = service.authorize(intent, policy)
    forged = mutation(trusted)
    broker = BrokerSpy()

    with pytest.raises(CredentialVerificationError):
        service.request_credential(intent, forged, _request(trusted), broker)
    assert broker.calls == 0


@pytest.mark.parametrize(
    "offset,expected",
    [
        (timedelta(minutes=-10), "receipt.expired"),
        (timedelta(minutes=5), "receipt.not_yet_valid"),
    ],
)
def test_credential_entrypoint_rejects_validly_signed_out_of_window_receipt(
    intent, policy, signer, verifier, state, offset, expected
):
    receipt = issue_decision_receipt(
        intent,
        evaluate_policy(policy, intent),
        signer,
        now=datetime.now(UTC) + offset,
        ttl_seconds=60,
    )
    broker = BrokerSpy()

    with pytest.raises(CredentialVerificationError, match=expected):
        AgentGuardService(signer, verifier, state).request_credential(
            intent, receipt, _request(receipt), broker
        )
    assert broker.calls == 0


def test_credential_entrypoint_rejects_changed_intent_without_broker_call(
    intent, policy, signer, verifier, state
):
    service = AgentGuardService(signer, verifier, state)
    receipt = service.authorize(intent, policy)
    changed = intent.model_copy(update={"request_id": "changed"})
    broker = BrokerSpy()

    with pytest.raises(CredentialVerificationError, match="intent_digest_mismatch"):
        service.request_credential(changed, receipt, _request(receipt), broker)
    assert broker.calls == 0


def test_approval_entrypoint_rejects_forged_require_approval_receipt(
    intent, policy, signer, verifier, state
):
    service = AgentGuardService(signer, verifier, state)
    allowed = service.authorize(intent, policy)
    forged = allowed.model_copy(update={"effect": Effect.REQUIRE_APPROVAL})

    with pytest.raises(ReceiptVerificationError, match="signature_invalid"):
        service.approve(
            intent,
            forged,
            approver_subject="security",
            reason="must not sign",
        )


def test_approval_entrypoint_rejects_expired_require_approval_receipt(
    intent, policy, signer, verifier, state
):
    pending_rule = policy.rules[1].model_copy(update={"effect": Effect.REQUIRE_APPROVAL})
    pending_policy = policy.model_copy(update={"rules": (pending_rule,)})
    expired = issue_decision_receipt(
        intent,
        evaluate_policy(pending_policy, intent),
        signer,
        now=datetime.now(UTC) - timedelta(minutes=10),
        ttl_seconds=60,
    )

    with pytest.raises(ReceiptVerificationError, match="receipt.expired"):
        AgentGuardService(signer, verifier, state).approve(
            intent,
            expired,
            approver_subject="security",
            reason="must not sign",
        )


def test_credential_entrypoint_rejects_forged_allow_receipt(
    intent, policy, signer, verifier, state
):
    pending_rule = policy.rules[1].model_copy(update={"effect": Effect.REQUIRE_APPROVAL})
    pending_policy = policy.model_copy(update={"rules": (pending_rule,)})
    service = AgentGuardService(signer, verifier, state)
    pending = service.authorize(intent, pending_policy)
    assert pending.effect == Effect.REQUIRE_APPROVAL
    forged = pending.model_copy(update={"effect": Effect.ALLOW})
    broker = BrokerSpy()

    with pytest.raises(CredentialVerificationError, match="signature_invalid"):
        service.request_credential(intent, forged, _request(pending), broker)
    assert broker.calls == 0


def test_approval_entrypoint_rejects_receipt_from_unknown_key(
    intent, policy, signer, verifier, state
):
    service = AgentGuardService(signer, verifier, state)
    other_service = AgentGuardService(Ed25519Signer.generate("unknown"), verifier, state)
    receipt = other_service.authorize(intent, policy)
    forged = receipt.model_copy(update={"effect": Effect.REQUIRE_APPROVAL})

    with pytest.raises(ReceiptVerificationError, match="signature_invalid"):
        service.approve(
            intent,
            forged,
            approver_subject="security",
            reason="must not sign",
        )
