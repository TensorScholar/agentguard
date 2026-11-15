from __future__ import annotations

from decisionlock.domain import (
    ActionIntent,
    AuthorityAnalysis,
    AuthorityOverprivilegeFinding,
    CapabilityScope,
    MinimalAuthorityRecommendation,
    PolicyCounterfactual,
    PolicyDecisionAnalysis,
    PolicyDocument,
    PolicyIntelligenceFindingType,
)


def derive_minimal_authority(intent: ActionIntent) -> MinimalAuthorityRecommendation:
    resource_types = None
    resource_ids = None
    if intent.resource is not None:
        resource_types = frozenset({intent.resource.type})
        resource_ids = frozenset({intent.resource.id}) if intent.resource.id is not None else None
    scope = CapabilityScope(
        capabilities=frozenset(intent.action.capabilities),
        protocols=frozenset({intent.action.protocol}),
        servers=frozenset({intent.action.server}),
        tools=frozenset({intent.action.tool}),
        operations=frozenset({intent.action.operation}),
        resource_types=resource_types,
        resource_ids=resource_ids,
        maximum_calls=1,
        delegable=False,
        maximum_delegation_depth=0,
    )
    rationale = (
        "exact action capabilities only",
        "exact protocol/server/tool/operation only",
        "exact resource type/id when present",
        "single execution use",
        "delegation disabled",
    )
    return MinimalAuthorityRecommendation(scope=scope, rationale=rationale)


def _extra(granted: frozenset[str] | None, required: frozenset[str] | None) -> tuple[str, ...]:
    if granted is None:
        return ("*",) if required is not None else ()
    if required is None:
        return tuple(sorted(granted))
    return tuple(sorted(granted - required))


def analyze_authority(intent: ActionIntent, granted: CapabilityScope) -> AuthorityAnalysis:
    recommendation = derive_minimal_authority(intent)
    required = recommendation.scope
    findings: list[AuthorityOverprivilegeFinding] = []

    dimensions = (
        (
            "capabilities",
            PolicyIntelligenceFindingType.OVERPRIVILEGED_CAPABILITY,
        ),
        ("protocols", PolicyIntelligenceFindingType.OVERPRIVILEGED_PROTOCOL),
        ("servers", PolicyIntelligenceFindingType.OVERPRIVILEGED_SERVER),
        ("tools", PolicyIntelligenceFindingType.OVERPRIVILEGED_TOOL),
        ("operations", PolicyIntelligenceFindingType.OVERPRIVILEGED_OPERATION),
        (
            "resource_types",
            PolicyIntelligenceFindingType.OVERPRIVILEGED_RESOURCE_TYPE,
        ),
        ("resource_ids", PolicyIntelligenceFindingType.OVERPRIVILEGED_RESOURCE_ID),
    )
    for name, finding_type in dimensions:
        extra = _extra(getattr(granted, name), getattr(required, name))
        if extra:
            findings.append(
                AuthorityOverprivilegeFinding(
                    finding_type=finding_type,
                    dimension=name,
                    granted=extra,
                    required=tuple(sorted(getattr(required, name) or ())),
                )
            )
    if granted.maximum_calls > required.maximum_calls:
        findings.append(
            AuthorityOverprivilegeFinding(
                finding_type=PolicyIntelligenceFindingType.EXCESS_CALL_BUDGET,
                dimension="maximum_calls",
                granted=granted.maximum_calls,
                required=required.maximum_calls,
            )
        )
    if granted.delegable or granted.maximum_delegation_depth > 0:
        findings.append(
            AuthorityOverprivilegeFinding(
                finding_type=PolicyIntelligenceFindingType.UNNEEDED_DELEGATION,
                dimension="delegation",
                granted=True,
                required=False,
            )
        )
    return AuthorityAnalysis(
        recommendation=recommendation,
        findings=tuple(findings),
        least_privilege=not findings,
    )


def analyze_policy_counterfactuals(
    policy: PolicyDocument, intent: ActionIntent
) -> PolicyDecisionAnalysis:
    from decisionlock.engine.policy import evaluate_policy

    baseline = evaluate_policy(policy, intent)
    counterfactuals: list[PolicyCounterfactual] = []
    for rule in sorted(baseline.matched_rules, key=lambda item: item.id):
        reduced = policy.model_copy(
            update={
                "rules": tuple(candidate for candidate in policy.rules if candidate.id != rule.id)
            }
        )
        result = evaluate_policy(reduced, intent)
        counterfactuals.append(
            PolicyCounterfactual(
                removed_rule_id=rule.id,
                effect=result.effect,
                reason_codes=result.reason_codes,
                selected_rule_id=(
                    result.selected_rule.id if result.selected_rule is not None else None
                ),
            )
        )
    return PolicyDecisionAnalysis(
        effect=baseline.effect,
        reason_codes=baseline.reason_codes,
        matched_rule_ids=tuple(rule.id for rule in baseline.matched_rules),
        selected_rule_id=(
            baseline.selected_rule.id if baseline.selected_rule is not None else None
        ),
        counterfactuals=tuple(counterfactuals),
    )
