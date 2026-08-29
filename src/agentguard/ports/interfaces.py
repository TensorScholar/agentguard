from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Protocol

from agentguard.domain import (
    ApprovalReceipt,
    AttestationMetadata,
    AuditEvent,
    AuthorityGrant,
    AuthorityGrantRecord,
    CapabilityLease,
    CredentialGrant,
    CredentialRequest,
    DecisionReceipt,
    ExecutionRecord,
    ExecutionResolution,
    ExecutionState,
    ProtectedExecutionResult,
    ReconciliationEvidence,
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
        execution_id: str,
        dispatching_at: datetime,
    ) -> ExecutionRecord: ...

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


class ExecutionReconciler(Protocol):
    def reconcile(self, execution: ExecutionRecord) -> ReconciliationEvidence: ...


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
    """Persistence boundary for AgentGuard security state."""


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
