from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .enums import (
    AuditEventType,
    AuthorityGrantStatus,
    CapabilityLeaseStatus,
    Effect,
    EnforcementMode,
    EvidenceTrustLevel,
    ExecutionState,
    ExecutionStatus,
    FieldReleaseType,
    PolicyIntelligenceFindingType,
    PreparedExecutionStatus,
    ProvenanceLabel,
    ReconciliationStatus,
    ReversibilityMode,
)


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

    @field_validator("expires_at")
    @classmethod
    def aware_expires_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("delegation expires_at must be timezone-aware")
        return value


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


class AuthorityReference(StrictModel):
    grant_id: str = Field(min_length=1, max_length=200)
    lease_id: str = Field(min_length=1, max_length=200)
    chain_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class FieldProvenanceStatement(StrictModel):
    schema_version: Literal["1"] = "1"
    statement_id: str = Field(min_length=1, max_length=200)
    request_id: str = Field(min_length=1, max_length=200)
    trace_id: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=200)
    field_path: str = Field(min_length=1, max_length=500, pattern=r"^/")
    value_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    semantic_type: str = Field(min_length=1, max_length=200)
    labels: frozenset[ProvenanceLabel] = Field(min_length=1)
    parent_statement_ids: tuple[str, ...] = Field(default=(), max_length=16)
    transformation: str | None = Field(default=None, max_length=300)
    issued_at: datetime
    expires_at: datetime
    key_id: str = Field(min_length=1, max_length=300)
    signature: str

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware_field_provenance_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("field provenance timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def field_provenance_times_consistent(self) -> "FieldProvenanceStatement":
        if self.issued_at >= self.expires_at:
            raise ValueError("field provenance times are inconsistent")
        if len(set(self.parent_statement_ids)) != len(self.parent_statement_ids):
            raise ValueError("field provenance parent ids must be unique")
        if self.statement_id in self.parent_statement_ids:
            raise ValueError("field provenance cannot parent itself")
        return self


class FieldReleaseReceipt(StrictModel):
    schema_version: Literal["1"] = "1"
    release_id: str = Field(min_length=1, max_length=200)
    request_id: str = Field(min_length=1, max_length=200)
    trace_id: str = Field(min_length=1, max_length=200)
    tenant_id: str = Field(min_length=1, max_length=200)
    principal_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    subject_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    action_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    resource_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    field_path: str = Field(min_length=1, max_length=500, pattern=r"^/")
    value_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    provenance_statement_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    semantic_type: str = Field(min_length=1, max_length=200)
    release_type: FieldReleaseType
    reason: str = Field(min_length=1, max_length=1000)
    issued_at: datetime
    expires_at: datetime
    key_id: str = Field(min_length=1, max_length=300)
    signature: str

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware_field_release_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("field release timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def field_release_times_consistent(self) -> "FieldReleaseReceipt":
        if self.issued_at >= self.expires_at:
            raise ValueError("field release times are inconsistent")
        return self


class FieldIntegrityBinding(StrictModel):
    integrity_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    release_set_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    expires_at: datetime | None = None
    release_ids: tuple[str, ...] = ()
    labels: frozenset[ProvenanceLabel] = frozenset()

    @field_validator("expires_at")
    @classmethod
    def aware_integrity_expiry(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("field integrity expiry must be timezone-aware")
        return value


class StagingRequirement(StrictModel):
    required: bool = False
    minimum_delay_seconds: int = Field(default=0, ge=0, le=86400)
    maximum_commit_window_seconds: int = Field(default=300, ge=1, le=86400)
    reversibility: ReversibilityMode = ReversibilityMode.IRREVERSIBLE
    require_fresh_approval: bool = False


class PreparedExecution(StrictModel):
    schema_version: Literal["1"] = "1"
    prepared_id: str = Field(min_length=1, max_length=200)
    execution_id: str = Field(min_length=1, max_length=200)
    decision_id: str = Field(min_length=1, max_length=200)
    request_id: str = Field(min_length=1, max_length=200)
    trace_id: str = Field(min_length=1, max_length=200)
    intent_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    prepared_binding_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    field_integrity_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    causal_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    status: PreparedExecutionStatus = PreparedExecutionStatus.PREPARED
    reversibility: ReversibilityMode
    prepared_at: datetime
    commit_not_before: datetime
    expires_at: datetime
    cancelled_at: datetime | None = None

    @field_validator("prepared_at", "commit_not_before", "expires_at", "cancelled_at")
    @classmethod
    def aware_prepared_times(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("prepared execution timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def prepared_times_consistent(self) -> "PreparedExecution":
        if not (self.prepared_at <= self.commit_not_before < self.expires_at):
            raise ValueError("prepared execution times are inconsistent")
        return self


class CausalGraphNode(StrictModel):
    execution_id: str = Field(min_length=1, max_length=200)
    parent_execution_ids: tuple[str, ...] = Field(default=(), max_length=16)
    intent_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    causal_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    causal_depth: int = Field(ge=0, le=64)
    labels: frozenset[ProvenanceLabel] = frozenset()
    tenant_id: str | None = Field(default=None, max_length=200)
    state: ExecutionState


class CausalExecutionGraph(StrictModel):
    schema_version: Literal["1"] = "1"
    root_execution_id: str = Field(min_length=1, max_length=200)
    nodes: tuple[CausalGraphNode, ...]
    graph_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")


class MinimalAuthorityRecommendation(StrictModel):
    scope: "CapabilityScope"
    rationale: tuple[str, ...]


class AuthorityOverprivilegeFinding(StrictModel):
    finding_type: PolicyIntelligenceFindingType
    dimension: str
    granted: tuple[str, ...] | int | bool
    required: tuple[str, ...] | int | bool


class AuthorityAnalysis(StrictModel):
    recommendation: MinimalAuthorityRecommendation
    findings: tuple[AuthorityOverprivilegeFinding, ...] = ()
    least_privilege: bool


class PolicyCounterfactual(StrictModel):
    removed_rule_id: str = Field(min_length=1, max_length=200)
    effect: Effect
    reason_codes: tuple[str, ...]
    selected_rule_id: str | None = None


class PolicyDecisionAnalysis(StrictModel):
    effect: Effect
    reason_codes: tuple[str, ...]
    matched_rule_ids: tuple[str, ...]
    selected_rule_id: str | None = None
    counterfactuals: tuple[PolicyCounterfactual, ...] = ()


class ActionIntent(StrictModel):
    schema_version: Literal["1"] = "1"
    request_id: str = Field(min_length=1, max_length=200)
    trace_id: str = Field(min_length=1, max_length=200)
    principal: Principal
    subject: Subject | None = None
    delegation: DelegationContext | None = None
    authority: AuthorityReference | None = None
    field_provenance: tuple[FieldProvenanceStatement, ...] = Field(default=(), max_length=64)
    field_releases: tuple[FieldReleaseReceipt, ...] = Field(default=(), max_length=32)
    causal_parent_execution_ids: tuple[str, ...] = Field(default=(), max_length=16)
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
        if value.tzinfo is None or value.utcoffset() is None:
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
    intent_digest: str
    principal_digest: str
    subject_digest: str | None = None
    action_digest: str
    resource_digest: str | None = None
    arguments_digest: str
    effects_digest: str
    tool_schema_digest: str
    policy_digest: str
    field_integrity_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    field_release_set_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    field_integrity_expires_at: datetime | None = None
    causal_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    causal_depth: int | None = Field(default=None, ge=0, le=64)
    staging_requirement: StagingRequirement | None = None
    credential_ceiling: CredentialCeiling | None = None
    execution_budget: ExecutionBudget = ExecutionBudget()
    enforcement_mode: EnforcementMode = EnforcementMode.ENFORCE
    issued_at: datetime
    not_before: datetime
    expires_at: datetime
    nonce: str
    key_id: str
    signature: str

    @field_validator("issued_at", "not_before", "expires_at")
    @classmethod
    def aware_security_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("decision receipt timestamps must be timezone-aware")
        return value

    @field_validator("field_integrity_expires_at")
    @classmethod
    def aware_field_integrity_expires_at(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("field integrity expiry must be timezone-aware")
        return value

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

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware_security_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("approval receipt timestamps must be timezone-aware")
        return value

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
    credential_handle_digest: str
    audience: str
    scopes: frozenset[str]
    tenant_id: str | None = None
    issued_at: datetime
    expires_at: datetime
    broker: str
    broker_key_id: str
    attestation: str

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware_security_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("credential grant timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_times(self) -> CredentialGrant:
        if self.issued_at >= self.expires_at:
            raise ValueError("credential grant times are inconsistent")
        if self.mode == "opaque_handle" and self.credential_handle is None:
            raise ValueError("opaque credential grants require a handle")
        if self.mode == "brokered_execution" and self.credential_handle is not None:
            raise ValueError("brokered execution grants cannot expose a handle")
        return self


class AuditCheckpoint(StrictModel):
    schema_version: Literal["1"] = "1"
    checkpoint_id: str = Field(min_length=1, max_length=200)
    ledger_id: str = Field(min_length=1, max_length=300)
    event_count: int = Field(ge=0)
    head_hash: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime
    key_id: str = Field(min_length=1, max_length=300)
    signature: str

    @field_validator("issued_at")
    @classmethod
    def aware_issued_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("audit checkpoint timestamp must be timezone-aware")
        return value


class EvidenceAttestation(StrictModel):
    schema_version: Literal["1"] = "1"
    manifest_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    issued_at: datetime
    key_id: str = Field(min_length=1, max_length=300)
    signature: str

    @field_validator("issued_at")
    @classmethod
    def aware_issued_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("evidence attestation timestamp must be timezone-aware")
        return value


class VerifiedCredentialAuthority(StrictModel):
    """Credential authority safe to retain and pass across the protected executor boundary."""

    grant_id: str
    issuance_id: str
    mode: Literal["opaque_handle", "brokered_execution"]
    credential_handle_digest: str
    audience: str
    scopes: frozenset[str]
    tenant_id: str | None = None
    expires_at: datetime
    broker: str
    broker_key_id: str

    @field_validator("expires_at")
    @classmethod
    def aware_expires_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("verified credential expiry must be timezone-aware")
        return value


class VerifiedExecution(StrictModel):
    """Immutable execution derived only from cryptographically and policy-validated inputs."""

    execution_id: str = Field(min_length=1, max_length=200)
    decision_id: str = Field(min_length=1, max_length=200)
    request_id: str = Field(min_length=1, max_length=200)
    trace_id: str = Field(min_length=1, max_length=200)
    intent: ActionIntent
    intent_digest: str
    policy_digest: str
    nonce: str = Field(min_length=1, repr=False)
    approval_id: str | None = None
    authority_grant_id: str | None = None
    authority_lease_id: str | None = None
    authority_chain_digest: str | None = None
    field_integrity_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    field_release_set_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    field_integrity_expires_at: datetime | None = None
    field_release_ids: tuple[str, ...] = ()
    causal_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    causal_depth: int = Field(default=0, ge=0, le=64)
    causal_labels: frozenset[ProvenanceLabel] = frozenset()
    causal_parent_execution_ids: tuple[str, ...] = Field(default=(), max_length=16)
    prepared_id: str | None = Field(default=None, max_length=200)
    credential_authority: VerifiedCredentialAuthority | None = None
    authorization_expires_at: datetime
    verified_at: datetime

    @field_validator("authorization_expires_at", "field_integrity_expires_at", "verified_at")
    @classmethod
    def aware_security_times(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("verified execution timestamps must be timezone-aware")
        return value


class ExecutionRecord(StrictModel):
    execution_id: str
    decision_id: str
    trace_id: str
    request_id: str
    intent_digest: str
    authority_digest: str
    policy_digest: str | None = None
    authority_grant_id: str | None = None
    authority_lease_id: str | None = None
    authority_chain_digest: str | None = None
    tenant_id: str | None = Field(default=None, max_length=200)
    principal_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    subject_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    field_integrity_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    field_release_set_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    field_integrity_expires_at: datetime | None = None
    causal_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    causal_depth: int = Field(default=0, ge=0, le=64)
    causal_labels: frozenset[ProvenanceLabel] = frozenset()
    causal_parent_execution_ids: tuple[str, ...] = Field(default=(), max_length=16)
    prepared_id: str | None = Field(default=None, max_length=200)
    state: ExecutionState
    reserved_at: datetime
    dispatching_at: datetime | None = None
    completed_at: datetime | None = None
    provider_status: int | None = None
    result_digest: str | None = None
    error_code: str | None = None

    @field_validator("reserved_at", "dispatching_at", "completed_at")
    @classmethod
    def aware_lifecycle_times(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("execution lifecycle timestamps must be timezone-aware")
        return value


class ProtectedExecutionResult(StrictModel):
    status: ExecutionStatus
    provider_status: int | None = None
    result_digest: str | None = None
    error_code: str | None = None


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

    @field_validator("started_at", "completed_at")
    @classmethod
    def aware_security_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("execution outcome timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_times(self) -> ExecutionOutcome:
        if self.started_at > self.completed_at:
            raise ValueError("execution outcome times are inconsistent")
        return self


class ReconciliationEvidence(StrictModel):
    status: ReconciliationStatus
    source: str = Field(min_length=1, max_length=300)
    evidence_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    observed_at: datetime
    trust_level: EvidenceTrustLevel = EvidenceTrustLevel.AGENTGUARD_SIGNED
    provider_operation_id: str | None = Field(default=None, max_length=500)
    error_code: str | None = Field(default=None, max_length=300)

    @field_validator("observed_at")
    @classmethod
    def aware_observed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("reconciliation evidence timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def enforce_confirmation_assurance(self) -> ReconciliationEvidence:
        if (
            self.status
            in {
                ReconciliationStatus.CONFIRMED_SUCCEEDED,
                ReconciliationStatus.CONFIRMED_FAILED,
            }
            and self.trust_level != EvidenceTrustLevel.PROVIDER_VERIFIED
        ):
            raise ValueError("reconciliation.confirmation_requires_provider_verified_evidence")
        return self


class ExecutionResolution(StrictModel):
    resolution_id: str = Field(min_length=1, max_length=200)
    execution_id: str = Field(min_length=1, max_length=200)
    original_state: ExecutionState
    status: ReconciliationStatus
    source: str = Field(min_length=1, max_length=300)
    evidence_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    trust_level: EvidenceTrustLevel
    provider_operation_id_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    observed_at: datetime
    reconciled_at: datetime
    error_code: str | None = Field(default=None, max_length=300)

    @field_validator("observed_at", "reconciled_at")
    @classmethod
    def aware_resolution_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("execution resolution timestamps must be timezone-aware")
        return value


class ExecutionAttestationPayload(StrictModel):
    schema_version: Literal["1"] = "1"
    attestation_id: str = Field(min_length=1, max_length=200)
    execution_id: str
    decision_id: str
    trace_id: str
    request_id: str
    intent_digest: str
    authority_digest: str
    policy_digest: str | None = None
    field_integrity_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    field_release_set_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    field_integrity_expires_at: datetime | None = None
    causal_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    causal_depth: int = Field(default=0, ge=0, le=64)
    prepared_id: str | None = Field(default=None, max_length=200)
    execution_state: ExecutionState
    reserved_at: datetime
    dispatching_at: datetime | None = None
    completed_at: datetime | None = None
    provider_status: int | None = None
    result_digest: str | None = None
    error_code: str | None = None
    resolution: ExecutionResolution | None = None
    previous_attestation_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    issued_at: datetime

    @field_validator(
        "reserved_at", "dispatching_at", "completed_at", "field_integrity_expires_at", "issued_at"
    )
    @classmethod
    def aware_attestation_times(cls, value: datetime | None) -> datetime | None:
        if value is not None and (value.tzinfo is None or value.utcoffset() is None):
            raise ValueError("execution attestation timestamps must be timezone-aware")
        return value


class ExecutionAttestation(StrictModel):
    payload: ExecutionAttestationPayload
    payload_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signer_key_id: str = Field(min_length=1, max_length=300)
    signature: str


class AttestationMetadata(StrictModel):
    attestation_id: str
    execution_id: str
    payload_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signature_digest: str = Field(pattern=r"^sha256:[0-9a-f]{64}$")
    signer_key_id: str
    previous_attestation_digest: str | None = Field(default=None, pattern=r"^sha256:[0-9a-f]{64}$")
    issued_at: datetime

    @field_validator("issued_at")
    @classmethod
    def aware_attestation_issued_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("attestation metadata timestamp must be timezone-aware")
        return value


class CapabilityScope(StrictModel):
    capabilities: frozenset[str] = frozenset()
    protocols: frozenset[str] | None = None
    servers: frozenset[str] | None = None
    tools: frozenset[str] | None = None
    operations: frozenset[str] | None = None
    resource_types: frozenset[str] | None = None
    resource_ids: frozenset[str] | None = None
    maximum_calls: int = Field(default=1, ge=1, le=1_000_000)
    delegable: bool = False
    maximum_delegation_depth: int = Field(default=0, ge=0, le=16)


class AuthorityGrant(StrictModel):
    schema_version: Literal["1"] = "1"
    grant_id: str = Field(min_length=1, max_length=200)
    parent_grant_id: str | None = Field(default=None, max_length=200)
    issuer: str = Field(min_length=1, max_length=300)
    subject: Principal
    scope: CapabilityScope
    depth: int = Field(ge=0, le=16)
    issued_at: datetime
    expires_at: datetime
    key_id: str = Field(min_length=1, max_length=300)
    signature: str

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware_authority_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("authority timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def authority_times_consistent(self) -> "AuthorityGrant":
        if self.issued_at >= self.expires_at:
            raise ValueError("authority grant times are inconsistent")
        return self


class AuthorityGrantRecord(StrictModel):
    grant: AuthorityGrant
    status: AuthorityGrantStatus
    remaining_calls: int = Field(ge=0, le=1_000_000)
    revoked_at: datetime | None = None
    revoke_reason: str | None = None


class CapabilityLease(StrictModel):
    schema_version: Literal["1"] = "1"
    lease_id: str = Field(min_length=1, max_length=200)
    grant_id: str = Field(min_length=1, max_length=200)
    maximum_uses: int = Field(ge=1, le=1_000_000)
    remaining_uses: int = Field(ge=0, le=1_000_000)
    issued_at: datetime
    expires_at: datetime
    status: CapabilityLeaseStatus = CapabilityLeaseStatus.ACTIVE

    @field_validator("issued_at", "expires_at")
    @classmethod
    def aware_lease_times(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("capability lease timestamps must be timezone-aware")
        return value

    @model_validator(mode="after")
    def lease_consistent(self) -> "CapabilityLease":
        if self.issued_at >= self.expires_at:
            raise ValueError("capability lease times are inconsistent")
        if self.remaining_uses > self.maximum_uses:
            raise ValueError("capability lease remaining uses exceed maximum")
        return self


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

    @field_validator("timestamp")
    @classmethod
    def aware_timestamp(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("audit event timestamp must be timezone-aware")
        return value
