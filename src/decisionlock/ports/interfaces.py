from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Protocol

from decisionlock.domain import (
    ApprovalReceipt,
    AttestationMetadata,
    AuditEvent,
    AuthorityGrant,
    AuthorityGrantRecord,
    CapabilityLease,
    CredentialAuthorityProfile,
    CredentialAuthorityProfileRecord,
    CredentialGrant,
    CredentialRequest,
    DecisionReceipt,
    ExecutionRecord,
    ExecutionResolution,
    ExecutionState,
    ExternalEffectBinding,
    PreparedExecution,
    ProtectedExecutionResult,
    ProviderIdentity,
    ProviderReconciliationEvidence,
    ReconciliationEvidence,
    VerifiedCredentialAuthority,
    VerifiedExecution,
)


class Clock(Protocol):
    def now(self) -> datetime: ...


class Signer(Protocol):
    @property
    def key_id(self) -> str: ...
    def sign(self, payload: bytes) -> bytes: ...


class SignatureVerifier(Protocol):
    def verify(self, key_id: str, payload: bytes, signature: bytes) -> bool: ...


class BrokerGrantVerifier(Protocol):
    def verify(
        self,
        broker_id: str,
        key_id: str,
        payload: bytes,
        signature: bytes,
    ) -> bool: ...


@dataclass(frozen=True, repr=False)
class ResolvedCredentialMaterial:
    """Ephemeral secret material. Callers must never persist, log, or serialize this value."""

    profile_id: str
    header_name: str
    header_value: str = field(repr=False)
    source_binding_digest: str


class CredentialMaterialSource(Protocol):
    @property
    def binding_digest(self) -> str: ...

    def read(self) -> str: ...


class CredentialProfileRepository(Protocol):
    def store_credential_profile(self, profile: CredentialAuthorityProfile) -> None: ...

    def get_credential_profile(
        self, profile_id: str
    ) -> CredentialAuthorityProfileRecord | None: ...

    def find_active_credential_profile(
        self, audience: str, tenant_id: str | None
    ) -> CredentialAuthorityProfileRecord | None: ...

    def get_credential_profile_by_binding_digest(
        self, binding_digest: str
    ) -> CredentialAuthorityProfileRecord | None: ...

    def revoke_credential_profile(
        self, profile_id: str, revoked_at: datetime, reason: str
    ) -> CredentialAuthorityProfileRecord: ...


class CredentialMaterialResolver(Protocol):
    def resolve(
        self,
        authority: VerifiedCredentialAuthority,
        provider: ProviderIdentity,
        *,
        now: datetime | None = None,
    ) -> ResolvedCredentialMaterial: ...


@dataclass(frozen=True)
class ResolvedToolSchema:
    schema: dict[str, Any]
    schema_digest: str
    discovered_at: datetime


class ToolSchemaResolver(Protocol):
    def resolve(self, server: str, tool: str) -> ResolvedToolSchema | None: ...


class NonceRepository(Protocol):
    """Legacy nonce-consumption compatibility port.

    New protected execution code must claim authority through ExecutionRepository.reserve_execution
    so the nonce claim and durable RESERVED record are atomic.
    """

    def consume(self, nonce: str, decision_id: str, consumed_at: datetime) -> bool: ...


class CredentialIssuanceRepository(Protocol):
    def register_approval(self, approval: ApprovalReceipt) -> None: ...

    def claim_credential_issuance(
        self,
        *,
        request_id: str,
        decision_id: str,
        approval_id: str | None,
        single_use: bool,
        claimed_at: datetime,
    ) -> str | None: ...

    def finish_credential_issuance(
        self,
        request_id: str,
        issuance_id: str | None,
        *,
        succeeded: bool,
        completed_at: datetime,
    ) -> None: ...


class ExecutionRepository(Protocol):
    def reserve_execution(
        self,
        verified_execution: VerifiedExecution,
        reserved_at: datetime,
    ) -> str | None: ...

    def mark_execution_dispatching(
        self,
        verified_execution: VerifiedExecution,
    ) -> datetime: ...

    def finish_execution(
        self,
        execution_id: str,
        terminal_state: ExecutionState,
        *,
        completed_at: datetime,
        provider_status: int | None = None,
        result_digest: str | None = None,
        error_code: str | None = None,
    ) -> ExecutionRecord: ...

    def get_execution(self, execution_id: str) -> ExecutionRecord | None: ...

    def list_executions(self) -> tuple[ExecutionRecord, ...]: ...

    def recover_incomplete_executions(
        self, recovered_at: datetime
    ) -> tuple[ExecutionRecord, ...]: ...

    def store_prepared_execution(self, prepared: PreparedExecution) -> None: ...

    def get_prepared_execution(self, prepared_id: str) -> PreparedExecution | None: ...

    def cancel_prepared_execution(
        self, prepared_id: str, cancelled_at: datetime
    ) -> PreparedExecution: ...

    def reserve_prepared_execution(
        self,
        prepared_id: str,
        verified_execution: VerifiedExecution,
        reserved_at: datetime,
    ) -> str | None: ...


class ExecutionReconciler(Protocol):
    def reconcile(self, execution: ExecutionRecord) -> ReconciliationEvidence: ...


class ProviderExecutionReconciler(Protocol):
    """Trusted provider-specific evidence collector for an exact external-effect binding."""

    def reconcile(self, binding: ExternalEffectBinding) -> ProviderReconciliationEvidence: ...


class ProviderEffectRepository(Protocol):
    """Durable sidecar store for non-secret provider bindings and digest-only evidence."""

    def store_external_effect_binding(
        self,
        execution_id: str,
        binding: ExternalEffectBinding,
        recorded_at: datetime,
    ) -> None: ...

    def get_external_effect_binding(self, execution_id: str) -> ExternalEffectBinding | None: ...

    def record_provider_reconciliation_evidence(
        self,
        evidence: ProviderReconciliationEvidence,
        recorded_at: datetime,
    ) -> None: ...

    def list_provider_reconciliation_evidence(
        self, binding_digest: str
    ) -> tuple[ProviderReconciliationEvidence, ...]: ...


class ReconciliationRepository(Protocol):
    def record_execution_resolution(
        self,
        execution_id: str,
        evidence: ReconciliationEvidence,
        reconciled_at: datetime,
    ) -> ExecutionResolution: ...

    def list_execution_resolutions(self, execution_id: str) -> tuple[ExecutionResolution, ...]: ...

    def get_latest_execution_resolution(self, execution_id: str) -> ExecutionResolution | None: ...


class AttestationRepository(Protocol):
    def record_attestation_metadata(self, metadata: AttestationMetadata) -> None: ...

    def get_latest_attestation_metadata(self, execution_id: str) -> AttestationMetadata | None: ...


class AuthorityRepository(Protocol):
    def store_authority_grant(self, grant: AuthorityGrant) -> None: ...

    def get_authority_grant(self, grant_id: str) -> AuthorityGrantRecord | None: ...

    def revoke_authority_grant(
        self, grant_id: str, revoked_at: datetime, reason: str
    ) -> AuthorityGrantRecord: ...

    def store_capability_lease(self, lease: CapabilityLease) -> None: ...

    def get_capability_lease(self, lease_id: str) -> CapabilityLease | None: ...

    def revoke_capability_lease(self, lease_id: str, revoked_at: datetime) -> CapabilityLease: ...


class AuditRepository(Protocol):
    def append(self, event: AuditEvent) -> AuditEvent: ...
    def verify(self) -> tuple[bool, int, str, str | None]: ...


class StateRepository(
    AuditRepository,
    NonceRepository,
    CredentialIssuanceRepository,
    ExecutionRepository,
    ReconciliationRepository,
    AttestationRepository,
    AuthorityRepository,
    Protocol,
):
    """Persistence boundary for DecisionLock security state."""


class CredentialBroker(Protocol):
    def issue(
        self,
        receipt: DecisionReceipt,
        request: CredentialRequest,
        approval: ApprovalReceipt | None = None,
    ) -> CredentialGrant: ...


class ProtectedExecutor(Protocol):
    """Trusted side-effect boundary.

    Implementations receive only VerifiedExecution and must derive action, target, and arguments
    from that immutable trusted representation rather than from caller-controlled raw request
    material.
    """

    def execute(self, verified_execution: VerifiedExecution) -> ProtectedExecutionResult: ...


class DefiniteExecutionFailure(RuntimeError):
    def __init__(
        self,
        error_code: str,
        *,
        provider_status: int | None = None,
        result_digest: str | None = None,
    ) -> None:
        super().__init__(error_code)
        self.error_code = error_code
        self.provider_status = provider_status
        self.result_digest = result_digest


class AmbiguousExecutionError(RuntimeError):
    def __init__(self, error_code: str = "execution.outcome_ambiguous") -> None:
        super().__init__(error_code)
        self.error_code = error_code
