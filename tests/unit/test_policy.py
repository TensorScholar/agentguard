from __future__ import annotations

from agentguard.domain import Effect, ExecutionBudget, ProvenanceLabel
from agentguard.domain.policy import EffectMatcher
from agentguard.engine.policy import evaluate_policy


def test_bounded_refund_allows(intent, policy):
    result = evaluate_policy(policy, intent)
    assert result.effect == Effect.ALLOW
    assert result.selected_rule and result.selected_rule.id == "bounded-refund"


def test_amount_over_limit_defaults_deny(intent, policy):
    changed = intent.model_copy(
        update={"effects": intent.effects.model_copy(update={"financial_amount_minor": 10001})}
    )
    assert evaluate_policy(policy, changed).effect == Effect.DENY


def test_external_content_high_impact_requires_approval(intent, policy):
    changed = intent.model_copy(
        update={"provenance": (ProvenanceLabel.EXTERNAL_EMAIL,), "provenance_verified": True}
    )
    result = evaluate_policy(policy, changed)
    assert result.effect == Effect.REQUIRE_APPROVAL
    assert result.selected_rule and result.selected_rule.id == "external-content-high-impact"


def test_cross_tenant_resource_denied(intent, policy):
    changed = intent.model_copy(
        update={"resource": intent.resource.model_copy(update={"owner_tenant": "other"})}
    )
    assert evaluate_policy(policy, changed).effect == Effect.DENY


def test_unverified_identity_denied(intent, policy):
    changed = intent.model_copy(
        update={"principal": intent.principal.model_copy(update={"identity_verified": False})}
    )
    assert evaluate_policy(policy, changed).effect == Effect.DENY


def test_unknown_provenance_cannot_auto_allow(intent, policy):
    changed = intent.model_copy(update={"provenance": (), "provenance_verified": False})
    result = evaluate_policy(policy, changed)
    assert result.effect != Effect.ALLOW


def test_unknown_capability_uses_fail_closed_default(intent, policy):
    changed = intent.model_copy(
        update={"action": intent.action.model_copy(update={"capabilities": frozenset({"unknown"})})}
    )
    assert evaluate_policy(policy, changed).effect == Effect.DENY


def test_unbounded_high_impact_requires_approval(intent, policy):
    selected = policy.rules[1].model_copy(
        update={"effects": EffectMatcher(), "execution_budget": ExecutionBudget()}
    )
    changed_policy = policy.model_copy(update={"rules": (selected,)})
    assert evaluate_policy(changed_policy, intent).effect == Effect.REQUIRE_APPROVAL


def test_missing_subject_denied(intent, policy):
    assert (
        evaluate_policy(policy, intent.model_copy(update={"subject": None})).effect == Effect.DENY
    )


def test_tool_mismatch_denied(intent, policy):
    changed = intent.model_copy(
        update={"action": intent.action.model_copy(update={"tool": "refund.delete"})}
    )
    assert evaluate_policy(policy, changed).effect == Effect.DENY


def test_deny_precedence(policy, intent):
    from agentguard.domain.policy import ActionMatcher, PolicyRule

    deny = PolicyRule(
        id="deny",
        priority=-100,
        effect=Effect.DENY,
        action=ActionMatcher(tools=frozenset({"refund.create"})),
    )
    changed = policy.model_copy(update={"rules": policy.rules + (deny,)})
    assert evaluate_policy(changed, intent).effect == Effect.DENY


def test_policy_digest_changes(policy, intent):
    a = evaluate_policy(policy, intent).policy_digest
    b = evaluate_policy(
        policy.model_copy(update={"metadata": policy.metadata.model_copy(update={"revision": 2})}),
        intent,
    ).policy_digest
    assert a != b
