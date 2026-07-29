from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agentguard.domain import Effect
from agentguard.engine.policy import evaluate_policy
from agentguard.engine.receipts import (
    ReceiptVerificationError,
    issue_decision_receipt,
    verify_decision_receipt,
    verify_intent_binding,
)


def make(intent, policy, signer):
    return issue_decision_receipt(
        intent,
        evaluate_policy(policy, intent),
        signer,
        now=datetime.now(UTC),
        ttl_seconds=60,
    )


def test_signed_receipt_verifies(intent, policy, signer, verifier):
    verify_decision_receipt(make(intent, policy, signer), verifier)


def test_signature_tampering_detected(intent, policy, signer, verifier):
    receipt = make(intent, policy, signer).model_copy(update={"reason_codes": ("tampered",)})
    with pytest.raises(ReceiptVerificationError, match="signature_invalid"):
        verify_decision_receipt(receipt, verifier)


def test_malformed_signature_encoding_is_rejected(intent, policy, signer, verifier):
    receipt = make(intent, policy, signer).model_copy(update={"signature": "not base64!"})
    with pytest.raises(ReceiptVerificationError, match="signature_invalid"):
        verify_decision_receipt(receipt, verifier)


def test_wrong_key_rejected(intent, policy, signer):
    from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier

    other = Ed25519Signer.generate()
    with pytest.raises(ReceiptVerificationError):
        verify_decision_receipt(
            make(intent, policy, signer), Ed25519Verifier({signer.key_id: other.public_key()})
        )


def test_expired_receipt_rejected(intent, policy, signer, verifier):
    now = datetime.now(UTC)
    receipt = issue_decision_receipt(
        intent,
        evaluate_policy(policy, intent),
        signer,
        now=now - timedelta(minutes=2),
        ttl_seconds=1,
    )
    with pytest.raises(ReceiptVerificationError, match="expired"):
        verify_decision_receipt(receipt, verifier, now=now, clock_skew_seconds=0)


def test_future_receipt_rejected(intent, policy, signer, verifier):
    now = datetime.now(UTC)
    receipt = issue_decision_receipt(
        intent,
        evaluate_policy(policy, intent),
        signer,
        now=now + timedelta(minutes=2),
        ttl_seconds=60,
    )
    with pytest.raises(ReceiptVerificationError, match="not_yet_valid"):
        verify_decision_receipt(receipt, verifier, now=now, clock_skew_seconds=0)


def test_argument_binding(intent, policy, signer):
    receipt = make(intent, policy, signer)
    verify_intent_binding(intent, receipt)
    changed = intent.model_copy(update={"arguments": {**intent.arguments, "amount_minor": 9999}})
    with pytest.raises(ReceiptVerificationError, match="arguments_digest_mismatch"):
        verify_intent_binding(changed, receipt)


def test_schema_binding(intent, policy, signer):
    receipt = make(intent, policy, signer)
    changed = intent.model_copy(
        update={"tool_schema": {"type": "object", "additionalProperties": True}}
    )
    with pytest.raises(ReceiptVerificationError, match="tool_schema_digest_mismatch"):
        verify_intent_binding(changed, receipt)


def test_receipt_contains_credential_ceiling(intent, policy, signer):
    receipt = make(intent, policy, signer)
    assert (
        receipt.effect == Effect.ALLOW
        and receipt.credential_ceiling
        and receipt.credential_ceiling.scopes == frozenset({"refund:create"})
    )
