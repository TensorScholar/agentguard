from __future__ import annotations

from datetime import datetime
from typing import Protocol

from agentguard.domain import (
    ApprovalReceipt,
    AuditEvent,
    CredentialGrant,
    CredentialRequest,
    DecisionReceipt,
)


class Clock(Protocol):
    def now(self) -> datetime: ...


class Signer(Protocol):
    @property
    def key_id(self) -> str: ...
    def sign(self, payload: bytes) -> bytes: ...


class SignatureVerifier(Protocol):
    def verify(self, key_id: str, payload: bytes, signature: bytes) -> bool: ...


class NonceRepository(Protocol):
    def consume(self, nonce: str, decision_id: str, consumed_at: datetime) -> bool: ...


class AuditRepository(Protocol):
    def append(self, event: AuditEvent) -> AuditEvent: ...
    def verify(self) -> tuple[bool, int, str, str | None]: ...


class StateRepository(AuditRepository, NonceRepository, Protocol):
    """Atomic persistence required by the application service."""


class CredentialBroker(Protocol):
    def issue(
        self,
        receipt: DecisionReceipt,
        request: CredentialRequest,
        approval: ApprovalReceipt | None = None,
    ) -> CredentialGrant: ...
