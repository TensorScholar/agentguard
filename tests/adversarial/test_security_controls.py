from __future__ import annotations

import pytest

from agentguard.adapters.broker import MockCredentialBroker
from agentguard.domain import CredentialRequest, ProvenanceLabel
from agentguard.engine.execution import ExecutionGuardError, authorize_execution
from agentguard.engine.policy import evaluate_policy
from agentguard.engine.receipts import issue_decision_receipt


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
    return r, MockCredentialBroker().issue(r, q)


def test_cross_tenant_reuse(intent, policy, signer, verifier, state):
    r, g = grant_for(intent, policy, signer)
    other = intent.model_copy(
        update={"principal": intent.principal.model_copy(update={"tenant_id": "other"})}
    )
    with pytest.raises(ExecutionGuardError, match="principal_digest_mismatch"):
        authorize_execution(other, r, g, verifier, state)


def test_resource_substitution(intent, policy, signer, verifier, state):
    r, g = grant_for(intent, policy, signer)
    other = intent.model_copy(
        update={"resource": intent.resource.model_copy(update={"id": "order-999"})}
    )
    with pytest.raises(ExecutionGuardError, match="resource_digest_mismatch"):
        authorize_execution(other, r, g, verifier, state)


def test_action_substitution(intent, policy, signer, verifier, state):
    r, g = grant_for(intent, policy, signer)
    other = intent.model_copy(
        update={"action": intent.action.model_copy(update={"tool": "refund.delete"})}
    )
    with pytest.raises(ExecutionGuardError, match="action_digest_mismatch"):
        authorize_execution(other, r, g, verifier, state)


def test_budget_amount_excess(intent, policy, signer, verifier, state):

    selected = policy.rules[1].model_copy(
        update={
            "execution_budget": policy.rules[1].execution_budget.model_copy(
                update={"maximum_financial_amount_minor": 8000}
            )
        }
    )
    narrowed = policy.model_copy(update={"rules": policy.rules[:1] + (selected,)})
    r, g = grant_for(intent, narrowed, signer)
    with pytest.raises(ExecutionGuardError, match="budget.financial_amount_exceeded"):
        authorize_execution(intent, r, g, verifier, state)


def test_untrusted_high_impact_never_auto_allows(intent, policy):
    changed = intent.model_copy(
        update={"provenance": (ProvenanceLabel.EXTERNAL_WEB_CONTENT,), "provenance_verified": True}
    )
    assert evaluate_policy(policy, changed).effect.value != "allow"
