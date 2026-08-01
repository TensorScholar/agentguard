from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import UTC, datetime
from fnmatch import fnmatchcase

from agentguard.domain import (
    ActionIntent,
    Effect,
    PolicyDocument,
    PolicyRule,
    ProvenanceLabel,
)

from .canonical import digest


@dataclass(frozen=True)
class PolicyEvaluation:
    effect: Effect
    reason_codes: tuple[str, ...]
    matched_rules: tuple[PolicyRule, ...]
    selected_rule: PolicyRule | None
    policy_digest: str


_EFFECT_RANK = {Effect.ALLOW: 0, Effect.REQUIRE_APPROVAL: 1, Effect.DENY: 2}


def _set_matches(value: str, patterns: Iterable[str]) -> bool:
    patterns = tuple(patterns)
    return not patterns or any(fnmatchcase(value, p) for p in patterns)


def _normalize_domain(value: str) -> str:
    candidate = value.strip().rstrip(".").casefold()
    if candidate.startswith("*."):
        return "*." + candidate[2:].encode("idna").decode("ascii")
    return candidate.encode("idna").decode("ascii")


def _domain_matches(value: str, patterns: Iterable[str]) -> bool:
    try:
        normalized = _normalize_domain(value)
        normalized_patterns = tuple(_normalize_domain(pattern) for pattern in patterns)
    except UnicodeError:
        return False
    return any(fnmatchcase(normalized, pattern) for pattern in normalized_patterns)


def rule_matches(rule: PolicyRule, intent: ActionIntent) -> bool:
    p = rule.principal
    if not _set_matches(intent.principal.agent_id, p.agent_ids):
        return False
    if not _set_matches(intent.principal.workload_id, p.workloads):
        return False
    if not _set_matches(intent.principal.tenant_id, p.tenant_ids):
        return False
    if p.verified_identity_required and not intent.principal.identity_verified:
        return False
    s = rule.subject
    if s.required and intent.subject is None:
        return False
    if s.user_ids and (
        intent.subject is None or not _set_matches(intent.subject.user_id, s.user_ids)
    ):
        return False
    a = rule.action
    if not _set_matches(intent.action.protocol, a.protocols):
        return False
    if not _set_matches(intent.action.server, a.servers):
        return False
    if not _set_matches(intent.action.tool, a.tools):
        return False
    if not _set_matches(intent.action.operation, a.operations):
        return False
    if a.capabilities_any and not (a.capabilities_any & intent.action.capabilities):
        return False
    r = rule.resource
    if r.types and (intent.resource is None or not _set_matches(intent.resource.type, r.types)):
        return False
    if r.tenant_from_principal and (
        intent.resource is None or intent.resource.owner_tenant != intent.principal.tenant_id
    ):
        return False
    if r.recipient_domains:
        if intent.resource is None or not intent.resource.recipient_domains:
            return False
        if not all(
            _domain_matches(d, r.recipient_domains) for d in intent.resource.recipient_domains
        ):
            return False
    if (
        r.excluded_recipient_domains
        and intent.resource is not None
        and any(
            _domain_matches(d, r.excluded_recipient_domains)
            for d in intent.resource.recipient_domains
        )
    ):
        return False
    pv = rule.provenance
    labels = set(intent.provenance)
    if pv.verified_required and not intent.provenance_verified:
        return False
    if pv.contains_any and not (pv.contains_any & labels):
        return False
    if pv.contains_only and not labels.issubset(pv.contains_only):
        return False
    if pv.deny_if_contains and not (pv.deny_if_contains & labels):
        return False
    e = rule.effects
    actual = intent.effects
    pairs = [
        (e.maximum_financial_amount_minor, actual.financial_amount_minor),
        (e.maximum_records_modified, actual.records_modified),
        (e.maximum_external_recipients, actual.external_recipients),
        (e.maximum_deleted_files, actual.deleted_files),
        (e.maximum_tool_calls, actual.tool_calls),
        (e.maximum_execution_seconds, actual.execution_seconds),
        (e.maximum_output_bytes, actual.output_bytes),
    ]
    for maximum, value in pairs:
        if maximum is not None and (value is None or value > maximum):
            return False
    return True


def evaluate_policy(
    policy: PolicyDocument,
    intent: ActionIntent,
    *,
    now: datetime | None = None,
) -> PolicyEvaluation:
    now = now or datetime.now(UTC)
    over_limit = [
        rule.id
        for rule in policy.rules
        if rule.credential is not None
        and rule.credential.maximum_ttl_seconds > policy.defaults.maximum_credential_ttl_seconds
    ]
    if over_limit:
        raise ValueError("policy.credential_ttl_exceeds_default:" + ",".join(sorted(over_limit)))
    delegation_reason = _delegation_rejection(intent, now)
    if delegation_reason is not None:
        return PolicyEvaluation(
            effect=Effect.DENY,
            reason_codes=(delegation_reason,),
            matched_rules=(),
            selected_rule=None,
            policy_digest=digest(policy),
        )
    matches = tuple(rule for rule in policy.rules if rule_matches(rule, intent))
    if not matches:
        return PolicyEvaluation(
            effect=policy.defaults.effect,
            reason_codes=("policy.default_deny",),
            matched_rules=(),
            selected_rule=None,
            policy_digest=digest(policy),
        )
    selected = max(matches, key=lambda r: (_EFFECT_RANK[r.effect], r.priority, r.id))
    reasons = tuple(
        (r.reason_code or f"policy.rule.{r.id}")
        for r in sorted(matches, key=lambda r: (-r.priority, r.id))
    )
    effect = selected.effect
    if effect == Effect.ALLOW and _unknown_provenance_requires_override(selected, intent):
        effect = policy.defaults.unknown_provenance
        reasons = ("policy.unknown_provenance", *reasons)
    if effect == Effect.ALLOW and "unknown" in intent.action.capabilities:
        effect = policy.defaults.unknown_capability
        reasons = ("policy.unknown_capability", *reasons)
    if effect == Effect.ALLOW and _has_unbounded_high_impact(selected, intent):
        effect = Effect.REQUIRE_APPROVAL
        reasons = ("policy.unbounded_high_impact", *reasons)
    return PolicyEvaluation(effect, reasons, matches, selected, digest(policy))


def _delegation_rejection(intent: ActionIntent, now: datetime) -> str | None:
    delegation = intent.delegation
    if delegation is None:
        return None
    if delegation.expires_at.tzinfo is None or delegation.expires_at.utcoffset() is None:
        return "delegation.timestamp_invalid"
    if delegation.expires_at <= now:
        return "delegation.expired"
    if not intent.action.capabilities.issubset(delegation.permitted_capabilities):
        return "delegation.capability_exceeded"
    return None


def _unknown_provenance_requires_override(rule: PolicyRule, intent: ActionIntent) -> bool:
    unknown = (
        not intent.provenance_verified
        or not intent.provenance
        or ProvenanceLabel.UNVERIFIED in intent.provenance
    )
    explicitly_accepted = ProvenanceLabel.UNVERIFIED in (
        rule.provenance.contains_any | rule.provenance.contains_only
    )
    return unknown and not explicitly_accepted


def _has_unbounded_high_impact(rule: PolicyRule, intent: ActionIntent) -> bool:
    required_fields = {
        "financial_mutation": ("financial_amount_minor",),
        "production_mutation": ("records_modified",),
        "bulk_data_export": ("records_modified", "output_bytes"),
        "destructive_filesystem": ("deleted_files",),
        "destructive_filesystem_operations": ("deleted_files",),
        "filesystem_delete": ("deleted_files",),
        "external_communication": ("external_recipients",),
    }
    maximum_fields = {
        "financial_amount_minor": "maximum_financial_amount_minor",
        "records_modified": "maximum_records_modified",
        "external_recipients": "maximum_external_recipients",
        "deleted_files": "maximum_deleted_files",
        "tool_calls": "maximum_tool_calls",
        "execution_seconds": "maximum_execution_seconds",
        "output_bytes": "maximum_output_bytes",
    }
    for capability in sorted(intent.action.capabilities):
        for field in required_fields.get(capability, ()):
            value = getattr(intent.effects, field)
            maximum_field = maximum_fields[field]
            policy_maximum = getattr(rule.effects, maximum_field)
            execution_maximum = getattr(rule.execution_budget, maximum_field)
            if value is None:
                return True
            if value > 0 and policy_maximum is None and execution_maximum is None:
                return True
    return False
