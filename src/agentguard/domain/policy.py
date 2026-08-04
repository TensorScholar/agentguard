from __future__ import annotations

from typing import Literal

from pydantic import Field, model_validator

from .enums import Effect, ProvenanceLabel
from .models import CredentialCeiling, ExecutionBudget, StrictModel


class PrincipalMatcher(StrictModel):
    agent_ids: frozenset[str] = frozenset()
    workloads: frozenset[str] = frozenset()
    tenant_ids: frozenset[str] = frozenset()
    verified_identity_required: bool = False


class SubjectMatcher(StrictModel):
    required: bool = False
    user_ids: frozenset[str] = frozenset()


class ActionMatcher(StrictModel):
    protocols: frozenset[str] = frozenset()
    servers: frozenset[str] = frozenset()
    tools: frozenset[str] = frozenset()
    operations: frozenset[str] = frozenset()
    capabilities_any: frozenset[str] = frozenset()


class ResourceMatcher(StrictModel):
    types: frozenset[str] = frozenset()
    tenant_from_principal: bool = False
    recipient_domains: frozenset[str] = frozenset()
    excluded_recipient_domains: frozenset[str] = frozenset()


class ProvenanceMatcher(StrictModel):
    contains_any: frozenset[ProvenanceLabel] = frozenset()
    contains_only: frozenset[ProvenanceLabel] = frozenset()
    deny_if_contains: frozenset[ProvenanceLabel] = frozenset()
    verified_required: bool = False


class EffectMatcher(StrictModel):
    maximum_financial_amount_minor: int | None = Field(default=None, ge=0)
    maximum_records_modified: int | None = Field(default=None, ge=0)
    maximum_external_recipients: int | None = Field(default=None, ge=0)
    maximum_deleted_files: int | None = Field(default=None, ge=0)
    maximum_tool_calls: int | None = Field(default=None, ge=0)
    maximum_execution_seconds: int | None = Field(default=None, ge=0)
    maximum_output_bytes: int | None = Field(default=None, ge=0)


class PolicyRule(StrictModel):
    id: str = Field(min_length=1, max_length=200)
    priority: int = Field(default=0, ge=-100000, le=100000)
    effect: Effect
    principal: PrincipalMatcher = PrincipalMatcher()
    subject: SubjectMatcher = SubjectMatcher()
    action: ActionMatcher = ActionMatcher()
    resource: ResourceMatcher = ResourceMatcher()
    provenance: ProvenanceMatcher = ProvenanceMatcher()
    effects: EffectMatcher = EffectMatcher()
    credential: CredentialCeiling | None = None
    execution_budget: ExecutionBudget = ExecutionBudget()
    reason_code: str | None = Field(default=None, max_length=300)

    @model_validator(mode="after")
    def deny_if_contains_requires_deny_effect(self) -> PolicyRule:
        if self.provenance.deny_if_contains and self.effect != Effect.DENY:
            raise ValueError(
                "provenance.deny_if_contains is incompatible with rule effect "
                f"'{self.effect.value}'; effect must be DENY"
            )
        return self


class PolicyDefaults(StrictModel):
    effect: Literal[Effect.DENY] = Effect.DENY
    maximum_credential_ttl_seconds: int = Field(default=60, ge=1, le=3600)
    unknown_provenance: Effect = Effect.REQUIRE_APPROVAL
    unknown_capability: Effect = Effect.DENY


class PolicyMetadata(StrictModel):
    id: str = Field(min_length=1, max_length=200)
    revision: int = Field(ge=1)
    description: str | None = Field(default=None, max_length=1000)


class PolicyDocument(StrictModel):
    schema_version: Literal["2"] = "2"
    metadata: PolicyMetadata
    defaults: PolicyDefaults = PolicyDefaults()
    rules: tuple[PolicyRule, ...]

    @model_validator(mode="after")
    def unique_rule_ids(self) -> PolicyDocument:
        ids = [rule.id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("policy rule ids must be unique")
        over_limit = [
            rule.id
            for rule in self.rules
            if rule.credential is not None
            and rule.credential.maximum_ttl_seconds > self.defaults.maximum_credential_ttl_seconds
        ]
        if over_limit:
            raise ValueError(
                "rule credential TTL exceeds policy default maximum: "
                + ", ".join(sorted(over_limit))
            )
        return self
