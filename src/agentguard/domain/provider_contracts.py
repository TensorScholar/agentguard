from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from .enums import EvidenceTrustLevel, ReconciliationStatus
from .models import StrictModel

_SHA256_PATTERN = r"^sha256:[0-9a-f]{64}$"


class IdempotencyMechanism(str, Enum):
    NONE = "none"
    CALLER_SUPPLIED_KEY = "caller_supplied_key"
    AGENTGUARD_GENERATED_KEY = "agentguard_generated_key"


class ReplayDisposition(str, Enum):
    FORBIDDEN = "forbidden"
    RECONCILE_BEFORE_RETRY = "reconcile_before_retry"
    SAME_IDEMPOTENCY_KEY_ONLY = "same_idempotency_key_only"


class ProviderIdentity(StrictModel):
    """Stable identity of the external authority that can realize an effect."""

    schema_version: Literal["1"] = "1"
    provider_id: str = Field(min_length=1, max_length=200)
    account_id: str | None = Field(default=None, max_length=300)
    tenant_id: str | None = Field(default=None, max_length=200)
    endpoint_digest: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def require_provider_scope(self) -> "ProviderIdentity":
        if self.account_id is None and self.endpoint_digest is None:
            raise ValueError("provider_identity.requires_account_or_endpoint")
        return self


class ExternalOperationIdentity(StrictModel):
    """AgentGuard-stable identity for one logical external operation."""

    schema_version: Literal["1"] = "1"
    operation_id: str = Field(min_length=1, max_length=200)
    operation_kind: str = Field(min_length=1, max_length=100)
    operation_name: str = Field(min_length=1, max_length=300)


class CredentialBinding(StrictModel):
    """Non-secret credential metadata bound to an external effect."""

    schema_version: Literal["1"] = "1"
    grant_id: str = Field(min_length=1, max_length=200)
    issuance_id: str = Field(min_length=1, max_length=200)
    credential_handle_digest: str = Field(pattern=_SHA256_PATTERN)
    audience: str = Field(min_length=1, max_length=500)
    scopes: frozenset[str] = Field(min_length=1)
    tenant_id: str | None = Field(default=None, max_length=200)
    broker: str = Field(min_length=1, max_length=300)
    broker_key_id: str = Field(min_length=1, max_length=300)


class ExecutionAttemptIdentity(StrictModel):
    """Identity and retry lineage for one dispatch attempt."""

    schema_version: Literal["1"] = "1"
    execution_id: str = Field(min_length=1, max_length=200)
    attempt_id: str = Field(min_length=1, max_length=200)
    attempt_number: int = Field(ge=1, le=1_000_000)
    parent_attempt_id: str | None = Field(default=None, max_length=200)
    started_at: datetime

    @field_validator("started_at")
    @classmethod
    def aware_started_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("execution attempt timestamp must be timezone-aware")
        return value

    @model_validator(mode="after")
    def validate_attempt_lineage(self) -> "ExecutionAttemptIdentity":
        if self.parent_attempt_id == self.attempt_id:
            raise ValueError("execution_attempt.cannot_parent_itself")
        if self.attempt_number == 1 and self.parent_attempt_id is not None:
            raise ValueError("execution_attempt.first_attempt_cannot_have_parent")
        if self.attempt_number > 1 and self.parent_attempt_id is None:
            raise ValueError("execution_attempt.retry_requires_parent")
        return self


class IdempotencyBinding(StrictModel):
    """Frozen replay contract for one external operation."""

    schema_version: Literal["1"] = "1"
    mechanism: IdempotencyMechanism = IdempotencyMechanism.NONE
    replay_disposition: ReplayDisposition = ReplayDisposition.RECONCILE_BEFORE_RETRY
    idempotency_key_digest: str | None = Field(default=None, pattern=_SHA256_PATTERN)

    @model_validator(mode="after")
    def validate_idempotency_semantics(self) -> "IdempotencyBinding":
        if self.mechanism == IdempotencyMechanism.NONE:
            if self.idempotency_key_digest is not None:
                raise ValueError("idempotency.none_forbids_key")
            if self.replay_disposition == ReplayDisposition.SAME_IDEMPOTENCY_KEY_ONLY:
                raise ValueError("idempotency.same_key_requires_key_mechanism")
        elif self.idempotency_key_digest is None:
            raise ValueError("idempotency.key_mechanism_requires_key_digest")
        return self


class ExternalEffectBinding(StrictModel):
    """Complete provider-effect contract consumed by credential and reconciliation phases."""

    schema_version: Literal["1"] = "1"
    decision_id: str = Field(min_length=1, max_length=200)
    intent_digest: str = Field(pattern=_SHA256_PATTERN)
    action_digest: str = Field(pattern=_SHA256_PATTERN)
    resource_digest: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    arguments_digest: str = Field(pattern=_SHA256_PATTERN)
    provider: ProviderIdentity
    operation: ExternalOperationIdentity
    credential: CredentialBinding | None = None
    attempt: ExecutionAttemptIdentity
    idempotency: IdempotencyBinding

    @model_validator(mode="after")
    def validate_replay_contract(self) -> "ExternalEffectBinding":
        if (
            self.attempt.attempt_number > 1
            and self.idempotency.replay_disposition == ReplayDisposition.FORBIDDEN
        ):
            raise ValueError("external_effect.retry_forbidden")
        return self


class ProviderEvidence(StrictModel):
    """Digest-only external evidence bound to exactly one ExternalEffectBinding."""

    schema_version: Literal["1"] = "1"
    binding_digest: str = Field(pattern=_SHA256_PATTERN)
    source: str = Field(min_length=1, max_length=300)
    evidence_digest: str = Field(pattern=_SHA256_PATTERN)
    trust_level: EvidenceTrustLevel
    observed_at: datetime
    provider_operation_id_digest: str | None = Field(default=None, pattern=_SHA256_PATTERN)
    provider_status: int | None = None
    error_code: str | None = Field(default=None, max_length=300)

    @field_validator("observed_at")
    @classmethod
    def aware_observed_at(cls, value: datetime) -> datetime:
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("provider evidence timestamp must be timezone-aware")
        return value


class ProviderReconciliationEvidence(ProviderEvidence):
    """Provider evidence with a reconciliation conclusion."""

    status: ReconciliationStatus

    @model_validator(mode="after")
    def enforce_confirmation_assurance(self) -> "ProviderReconciliationEvidence":
        if (
            self.status
            in {
                ReconciliationStatus.CONFIRMED_SUCCEEDED,
                ReconciliationStatus.CONFIRMED_FAILED,
            }
            and self.trust_level != EvidenceTrustLevel.PROVIDER_VERIFIED
        ):
            raise ValueError("provider_reconciliation.confirmation_requires_provider_verified")
        return self
