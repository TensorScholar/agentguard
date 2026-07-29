from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agentguard.adapters.broker import MockCredentialBroker
from agentguard.adapters.crypto import Ed25519Signer
from agentguard.domain import CredentialRequest
from agentguard.engine.credentials import (
    CredentialVerificationError,
    attest_credential_grant,
    validate_credential_request,
    verify_credential_grant,
)
from agentguard.engine.policy import evaluate_policy
from agentguard.engine.receipts import issue_decision_receipt


def setup(intent, policy, signer):
    r = issue_decision_receipt(intent, evaluate_policy(policy, intent), signer)
    c = r.credential_ceiling
    q = CredentialRequest(
        request_id="cr",
        trace_id=r.trace_id,
        decision_id=r.decision_id,
        audience=c.audience,
        scopes=c.scopes,
        requested_ttl_seconds=30,
        tenant_id=c.tenant_id,
    )
    return r, q


def test_mock_broker_returns_authenticated_opaque_handle(intent, policy, signer):
    r, q = setup(intent, policy, signer)
    broker = MockCredentialBroker()
    g = broker.issue(r, q)
    assert g.mode == "opaque_handle" and g.credential_handle.startswith("opaque://")
    assert g.credential_handle not in repr(g)
    verify_credential_grant(r, g, broker.verifier)


def test_requested_scope_excess_rejected(intent, policy, signer):
    r, q = setup(intent, policy, signer)
    q = q.model_copy(update={"scopes": frozenset({"refund:create", "refund:delete"})})
    with pytest.raises(CredentialVerificationError, match="requested_scope_exceeds"):
        validate_credential_request(r, q)


def test_requested_ttl_excess_rejected(intent, policy, signer):
    r, q = setup(intent, policy, signer)
    q = q.model_copy(update={"requested_ttl_seconds": 61})
    with pytest.raises(CredentialVerificationError, match="requested_ttl_exceeds"):
        validate_credential_request(r, q)


def test_request_audience_mismatch(intent, policy, signer):
    r, q = setup(intent, policy, signer)
    q = q.model_copy(update={"audience": "other"})
    with pytest.raises(CredentialVerificationError, match="audience_mismatch"):
        validate_credential_request(r, q)


def test_grant_scope_inflation_rejected(intent, policy, signer):
    r, q = setup(intent, policy, signer)
    broker_signer = Ed25519Signer.generate("broker-key")
    broker = MockCredentialBroker(signer=broker_signer)
    g = attest_credential_grant(
        broker.issue(r, q).model_copy(update={"scopes": frozenset({"refund:create", "admin"})}),
        broker_signer,
    )
    with pytest.raises(CredentialVerificationError, match="scope_exceeds"):
        verify_credential_grant(r, g, broker.verifier)


def test_grant_ttl_inflation_rejected(intent, policy, signer):
    r, q = setup(intent, policy, signer)
    broker_signer = Ed25519Signer.generate("broker-key")
    broker = MockCredentialBroker(signer=broker_signer)
    g = broker.issue(r, q)
    g = attest_credential_grant(
        g.model_copy(update={"expires_at": g.issued_at + timedelta(seconds=61)}),
        broker_signer,
    )
    with pytest.raises(CredentialVerificationError, match="ttl_exceeds"):
        verify_credential_grant(r, g, broker.verifier)


def test_grant_tenant_mismatch_rejected(intent, policy, signer):
    r, q = setup(intent, policy, signer)
    broker_signer = Ed25519Signer.generate("broker-key")
    broker = MockCredentialBroker(signer=broker_signer)
    g = attest_credential_grant(
        broker.issue(r, q).model_copy(update={"tenant_id": "other"}),
        broker_signer,
    )
    with pytest.raises(CredentialVerificationError, match="tenant_mismatch"):
        verify_credential_grant(r, g, broker.verifier)


def test_future_grant_rejected(intent, policy, signer):
    r, q = setup(intent, policy, signer)
    now = datetime.now(UTC)
    broker_signer = Ed25519Signer.generate("broker-key")
    broker = MockCredentialBroker(signer=broker_signer)
    g = attest_credential_grant(
        broker.issue(r, q).model_copy(
            update={
                "issued_at": now + timedelta(seconds=10),
                "expires_at": now + timedelta(seconds=20),
            }
        ),
        broker_signer,
    )
    with pytest.raises(CredentialVerificationError, match="not_yet_valid"):
        verify_credential_grant(r, g, broker.verifier, now=now)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda grant: grant.model_copy(update={"attestation": ""}),
        lambda grant: grant.model_copy(update={"attestation": "malformed!"}),
        lambda grant: grant.model_copy(update={"broker_key_id": "unknown-key"}),
        lambda grant: grant.model_copy(update={"broker": "unknown-broker"}),
        lambda grant: grant.model_copy(update={"decision_id": "forged-decision"}),
        lambda grant: grant.model_copy(update={"trace_id": "forged-trace"}),
        lambda grant: grant.model_copy(update={"issuance_id": "forged-issuance"}),
        lambda grant: grant.model_copy(update={"audience": "forged-audience"}),
        lambda grant: grant.model_copy(update={"scopes": frozenset({"admin"})}),
        lambda grant: grant.model_copy(update={"tenant_id": "forged-tenant"}),
        lambda grant: grant.model_copy(
            update={"issued_at": grant.issued_at - timedelta(seconds=1)}
        ),
        lambda grant: grant.model_copy(
            update={"expires_at": grant.expires_at + timedelta(seconds=1)}
        ),
        lambda grant: grant.model_copy(update={"mode": "brokered_execution"}),
        lambda grant: grant.model_copy(update={"credential_handle": "opaque://tampered"}),
        lambda grant: grant.model_copy(update={"credential_handle_digest": "forged-digest"}),
    ],
)
def test_unsigned_unknown_and_tampered_grants_fail_closed(intent, policy, signer, mutation):
    r, q = setup(intent, policy, signer)
    broker = MockCredentialBroker()
    grant = mutation(broker.issue(r, q))

    with pytest.raises(CredentialVerificationError):
        verify_credential_grant(r, grant, broker.verifier)


def test_grant_from_unknown_broker_fails_closed(intent, policy, signer):
    r, q = setup(intent, policy, signer)
    trusted = MockCredentialBroker(name="trusted")
    unknown = MockCredentialBroker(name="unknown")

    with pytest.raises(CredentialVerificationError, match="attestation_invalid"):
        verify_credential_grant(r, unknown.issue(r, q), trusted.verifier)


def test_grant_requires_explicit_verifier(intent, policy, signer):
    r, q = setup(intent, policy, signer)
    grant = MockCredentialBroker().issue(r, q)

    with pytest.raises(CredentialVerificationError, match="verifier_unavailable"):
        verify_credential_grant(r, grant, None)
