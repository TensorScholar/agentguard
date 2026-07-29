from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import AuditEventType, Effect, EnforcementMode, ExecutionStatus, ProvenanceLabel


class StrictModel(BaseModel):
    model_config = ConfigDict(strict=True, extra="forbid", frozen=True)


class Principal(StrictModel):
    agent_id: str = Field(min_length=1, max_length=200)
    workload_id: str = Field(min_length=1, max_length=300)
    tenant_id: str = Field(min_length=1, max_length=200)
    runtime_identity: str | None = Field(default=None, max_length=500)
    identity_verified: bool = False
    identity_issuer: str | None = Field(default=None, max_length=300)


class Subject(StrictModel):
    user_id: str = Field(min_length=1, max_length=200)
    tenant_id: str | None = Field(default=None, max_length=200)
    authentication_level: str | None = Field(default=None, max_length=100)


class DelegationContext(StrictModel):
    delegation_id: str = Field(min_length=1, max_length=200)
    depth: int = Field(ge=0, le=16)
    permitted_capabilities: frozenset[str] = frozenset()
    expires_at: datetime


class Action(StrictModel):
    protocol: str = Field(min_length=1, max_length=50)
    server: str = Field(min_length=1, max_length=300)
    tool: str = Field(min_length=1, max_length=300)
    operation: str = Field(min_length=1, max_length=100)
    capabilities: frozenset[str] = frozenset()


class Resource(StrictModel):
    type: str = Field(min_length=1, max_length=100)
    id: str | None = Field(default=None, max_length=500)
    owner_tenant: str | None = Field(default=None, max_length=200)
    recipient_domains: tuple[str, ...] = ()
    attributes: dict[str, str | int | bool] = Field(default_factory=dict)


class EffectProjection(StrictModel):
    currency: Literal["USD"] = "USD"
    financial_amount_minor: int | None = Field(default=None, ge=0)
    records_modified: int | None = Field(default=None, ge=0)
    external_recipients: int | None = Field(default=None, ge=0)
    deleted_files: int | None = Field(default=None, ge=0)
    tool_calls: int | None = Field(default=None, ge=0)
    execution_seconds: int | None = Field(default=None, ge=0)
    output_bytes: int | None = Field(default=None, ge=0)


class ActionIntent(StrictModel):
    schema_version: Literal["1"] = "1"
    request_id: str = Field(min_length=1, max_length=200)
    trace_id: str = Field(min_length=1, max_length=200)
    principal: Principal
    subject: Subject | None = None
    delegation: DelegationContext | None = None
    action: Action
    resource: Resource | None = None
    provenance: tuple[ProvenanceLabel, ...] = ()
    provenance_verified: bool = False
    effects: EffectProjection = EffectProjection()
    arguments: dict[str, Any] = Field(default_factory=dict)
    tool_schema: dict[str, Any] = Field(default_factory=dict)
    requested_at: datetime

    @field_validator("requested_at")
    @classmethod
    def aware_requested_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None:
            raise ValueError("requested_at must be timezone-aware")
        return value


class CredentialCeiling(StrictModel):
    audience: str = Field(min_length=1, max_length=500)
    scopes: frozenset[str] = Field(min_length=1)
    maximum_ttl_seconds: int = Field(ge=1, le=3600)
    single_use: bool = True
    tenant_id: str | None = Field(default=None, max_length=200)


class ExecutionBudget(StrictModel):
    maximum_financial_amount_minor: int | None = Field(default=None, ge=0)
    maximum_records_modified: int | None = Field(default=None, ge=0)
    maximum_external_recipients: int | None = Field(default=None, ge=0)
    maximum_deleted_files: int | None = Field(default=None, ge=0)
    maximum_tool_calls: int | None = Field(default=None, ge=0)
    maximum_execution_seconds: int | None = Field(default=None, ge=0)
    maximum_output_bytes: int | None = Field(default=None, ge=0)


class DecisionReceipt(StrictModel):
    schema_version: Literal["1"] = "1"
    decision_id: str
    request_id: str
    trace_id: str
    effect: Effect
    reason_codes: tuple[str, ...]
    matched_rule_ids: tuple[str, ...] = ()
    principal_digest: str
    subject_digest: str | None = None
    action_digest: str
    resource_digest: str | None = None
    arguments_digest: str
    effects_digest: str
    tool_schema_digest: str
    policy_digest: str
    credential_ceiling: CredentialCeiling | None = None
    execution_budget: ExecutionBudget = ExecutionBudget()
    enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    nonce: str
    key_id: str
    signature: str

    @model_validator(mode="after")
    def validate_times(self) -> DecisionReceipt:
        if not (self.issued_at <= self.not_before <= self.expires_at):
            raise ValueError("receipt times are inconsistent")
        return self


class ApprovalReceipt(StrictModel):
    schema_version: Literal["1"] = "1"
    approval_id: str
    decision_id: str
    trace_id: str
    approver_subject: str
    authentication_level: str | None = None
    approved_action_digest: str
    approved_resource_digest: str | None = None
    approved_arguments_digest: str
    approved_budget: ExecutionBudget = ExecutionBudget()
    reason: str = Field(min_length=1, max_length=1000)
    maximum_uses: int = Field(default=1, ge=1, le=100)
    issued_at: datetime
    expires_at: datetime
    key_id: str
    signature: str

    @model_validator(mode="after")
    def validate_times(self) -> ApprovalReceipt:
        if self.issued_at > self.expires_at:
            raise ValueError("approval receipt times are inconsistent")
        return self


class CredentialRequest(StrictModel):
    schema_version: Literal["1"] = "1"
    request_id: str
    trace_id: str
    decision_id: str
    audience: str
    scopes: frozenset[str]
    requested_ttl_seconds: int = Field(ge=1, le=3600)
    tenant_id: str | None = None
    approval_id: str | None = None


class CredentialGrant(StrictModel):
    schema_version: Literal["1"] = "1"
    grant_id: str
    issuance_id: str
    decision_id: str
    trace_id: str
    mode: Literal["opaque_handle", "brokered_execution"]
    credential_handle: str | None = Field(default=None, repr=False)
    audience: str
    scopes: frozenset[str]
    tenant_id: str | None = None
    issued_at: datetime
    expires_at: datetime
    broker: str

    @model_validator(mode="after")
    def validate_times(self) -> CredentialGrant:
        if self.issued_at >= self.expires_at:
            raise ValueError("credential grant times are inconsistent")
        return self


class ExecutionRequest(StrictModel):
    schema_version: Literal["1"] = "1"
    execution_id: str
    trace_id: str
    intent: ActionIntent
    receipt: DecisionReceipt
    credential_grant: CredentialGrant | None = None
    approval_receipt: ApprovalReceipt | None = None


class ExecutionOutcome(StrictModel):
    schema_version: Literal["1"] = "1"
    execution_id: str
    trace_id: str
    decision_id: str
    status: ExecutionStatus
    provider_status: int | None = None
    result_digest: str | None = None
    error_code: str | None = None
    started_at: datetime
    completed_at: datetime


class AuditEvent(StrictModel):
    schema_version: Literal["1"] = "1"
    event_id: str
    sequence: int | None = None
    event_type: AuditEventType
    timestamp: datetime
    trace_id: str
    request_id: str | None = None
    decision_id: str | None = None
    approval_id: str | None = None
    issuance_id: str | None = None
    execution_id: str | None = None
    source: str
    reason_code: str | None = None
    data: dict[str, str | int | bool | None] = Field(default_factory=dict)
    previous_hash: str | None = None
    event_hash: str | None = None
