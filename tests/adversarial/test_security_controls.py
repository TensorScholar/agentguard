from __future__ import annotations

import pytest

from decisionlock.adapters.broker import MockCredentialBroker
from decisionlock.domain import CredentialRequest, ProvenanceLabel
from decisionlock.engine.execution import ExecutionGuardError, preflight_execution
from decisionlock.engine.policy import evaluate_policy
from decisionlock.engine.receipts import issue_decision_receipt


def grant_for(intent, policy, signer):
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
    broker = MockCredentialBroker()
    return r, broker.issue(r, q), broker.verifier


def test_cross_tenant_reuse(intent, policy, signer, verifier, state):
    r, g, grant_verifier = grant_for(intent, policy, signer)
    other = intent.model_copy(
        update={"principal": intent.principal.model_copy(update={"tenant_id": "other"})}
    )
    with pytest.raises(ExecutionGuardError, match="principal_digest_mismatch"):
        preflight_execution(
            other,
            r,
            g,
            verifier,
            state,
            broker_grant_verifier=grant_verifier,
            current_policy=policy,
        )


def test_resource_substitution(intent, policy, signer, verifier, state):
    r, g, grant_verifier = grant_for(intent, policy, signer)
    other = intent.model_copy(
        update={"resource": intent.resource.model_copy(update={"id": "order-999"})}
    )
    with pytest.raises(ExecutionGuardError, match="resource_digest_mismatch"):
        preflight_execution(
            other,
            r,
            g,
            verifier,
            state,
            broker_grant_verifier=grant_verifier,
            current_policy=policy,
        )


def test_action_substitution(intent, policy, signer, verifier, state):
    r, g, grant_verifier = grant_for(intent, policy, signer)
    other = intent.model_copy(
        update={"action": intent.action.model_copy(update={"tool": "refund.delete"})}
    )
    with pytest.raises(ExecutionGuardError, match="action_digest_mismatch"):
        preflight_execution(
            other,
            r,
            g,
            verifier,
            state,
            broker_grant_verifier=grant_verifier,
            current_policy=policy,
        )


def test_budget_amount_excess(intent, policy, signer, verifier, state):

    selected = policy.rules[1].model_copy(
        update={
            "execution_budget": policy.rules[1].execution_budget.model_copy(
                update={"maximum_financial_amount_minor": 8000}
            )
        }
    )
    narrowed = policy.model_copy(update={"rules": policy.rules[:1] + (selected,)})
    r, g, grant_verifier = grant_for(intent, narrowed, signer)
    with pytest.raises(ExecutionGuardError, match="budget.financial_amount_exceeded"):
        preflight_execution(
            intent,
            r,
            g,
            verifier,
            state,
            broker_grant_verifier=grant_verifier,
            current_policy=narrowed,
        )


def test_untrusted_high_impact_never_auto_allows(intent, policy):
    changed = intent.model_copy(
        update={"provenance": (ProvenanceLabel.EXTERNAL_WEB_CONTENT,), "provenance_verified": True}
    )
    assert evaluate_policy(policy, changed).effect.value != "allow"
