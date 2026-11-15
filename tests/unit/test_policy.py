from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from decisionlock.domain import (
    DelegationContext,
    Effect,
    EffectProjection,
    ExecutionBudget,
    PolicyDocument,
    ProvenanceLabel,
)
from decisionlock.domain.policy import EffectMatcher
from decisionlock.engine.policy import evaluate_policy


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


@pytest.mark.parametrize(
    "capability",
    [
        "financial_mutation",
        "production_mutation",
        "bulk_data_export",
        "destructive_filesystem",
        "destructive_filesystem_operations",
        "filesystem_delete",
        "external_communication",
    ],
)
def test_unknown_high_impact_projection_never_auto_allows(intent, policy, capability):
    selected = policy.rules[1].model_copy(
        update={"effects": EffectMatcher(), "execution_budget": ExecutionBudget()}
    )
    changed_policy = policy.model_copy(update={"rules": (selected,)})
    changed = intent.model_copy(
        update={
            "action": intent.action.model_copy(update={"capabilities": frozenset({capability})}),
            "effects": EffectProjection(),
        }
    )
    result = evaluate_policy(changed_policy, changed)
    assert result.effect == Effect.REQUIRE_APPROVAL
    assert result.reason_codes[0] == "policy.unbounded_high_impact"


def test_zero_high_impact_projection_is_not_treated_as_unknown(intent, policy):
    selected = policy.rules[1].model_copy(
        update={"effects": EffectMatcher(), "execution_budget": ExecutionBudget()}
    )
    changed_policy = policy.model_copy(update={"rules": (selected,)})
    zero = intent.model_copy(
        update={"effects": intent.effects.model_copy(update={"financial_amount_minor": 0})}
    )
    assert evaluate_policy(changed_policy, zero).effect == Effect.ALLOW


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
    from decisionlock.domain.policy import ActionMatcher, PolicyRule

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


def test_delegation_capability_subset_allows(intent, policy):
    delegated = intent.model_copy(
        update={
            "delegation": DelegationContext(
                delegation_id="delegation",
                depth=1,
                permitted_capabilities=frozenset({"financial_mutation", "filesystem_read"}),
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        }
    )
    assert evaluate_policy(policy, delegated).effect == Effect.ALLOW


def test_expired_delegation_denies_with_stable_reason(intent, policy):
    delegated = intent.model_copy(
        update={
            "delegation": DelegationContext(
                delegation_id="expired",
                depth=1,
                permitted_capabilities=frozenset({"financial_mutation"}),
                expires_at=datetime.now(UTC) - timedelta(seconds=1),
            )
        }
    )
    result = evaluate_policy(policy, delegated)
    assert result.effect == Effect.DENY
    assert result.reason_codes == ("delegation.expired",)


@pytest.mark.parametrize(
    "permitted",
    [frozenset(), frozenset({"filesystem_read"})],
)
def test_delegation_cannot_increase_capability_authority(intent, policy, permitted):
    delegated = intent.model_copy(
        update={
            "delegation": DelegationContext(
                delegation_id="too-narrow",
                depth=1,
                permitted_capabilities=permitted,
                expires_at=datetime.now(UTC) + timedelta(minutes=5),
            )
        }
    )
    result = evaluate_policy(policy, delegated)
    assert result.effect == Effect.DENY
    assert result.reason_codes == ("delegation.capability_exceeded",)


def test_policy_default_credential_ttl_rejects_wider_rule(policy):
    data = policy.model_dump(mode="json")
    data["defaults"]["maximum_credential_ttl_seconds"] = 30
    with pytest.raises(ValidationError, match="credential TTL exceeds"):
        PolicyDocument.model_validate_json(json.dumps(data))


def test_runtime_rejects_policy_copy_with_wider_rule_ttl(policy, intent):
    invalid = policy.model_copy(
        update={
            "defaults": policy.defaults.model_copy(update={"maximum_credential_ttl_seconds": 30})
        }
    )
    with pytest.raises(ValueError, match="policy.credential_ttl_exceeds_default"):
        evaluate_policy(invalid, intent)
