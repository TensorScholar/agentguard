from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from agentguard.adapters.broker import MockCredentialBroker
from agentguard.domain import CredentialRequest
from agentguard.engine.credentials import (
    CredentialVerificationError,
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


def test_mock_broker_returns_opaque_handle(intent, policy, signer):
    r, q = setup(intent, policy, signer)
    g = MockCredentialBroker().issue(r, q)
    assert g.mode == "opaque_handle" and g.credential_handle.startswith("opaque://")
    assert g.credential_handle not in repr(g)


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
    g = (
        MockCredentialBroker()
        .issue(r, q)
        .model_copy(update={"scopes": frozenset({"refund:create", "admin"})})
    )
    with pytest.raises(CredentialVerificationError, match="scope_exceeds"):
        verify_credential_grant(r, g)


def test_grant_ttl_inflation_rejected(intent, policy, signer):
    r, q = setup(intent, policy, signer)
    g = MockCredentialBroker().issue(r, q)
    g = g.model_copy(update={"expires_at": g.issued_at + timedelta(seconds=61)})
    with pytest.raises(CredentialVerificationError, match="ttl_exceeds"):
        verify_credential_grant(r, g)


def test_grant_tenant_mismatch_rejected(intent, policy, signer):
    r, q = setup(intent, policy, signer)
    g = MockCredentialBroker().issue(r, q).model_copy(update={"tenant_id": "other"})
    with pytest.raises(CredentialVerificationError, match="tenant_mismatch"):
        verify_credential_grant(r, g)


def test_future_grant_rejected(intent, policy, signer):
    r, q = setup(intent, policy, signer)
    now = datetime.now(UTC)
    g = (
        MockCredentialBroker()
        .issue(r, q)
        .model_copy(
            update={
                "issued_at": now + timedelta(seconds=10),
                "expires_at": now + timedelta(seconds=20),
            }
        )
    )
    with pytest.raises(CredentialVerificationError, match="not_yet_valid"):
        verify_credential_grant(r, g, now=now)
