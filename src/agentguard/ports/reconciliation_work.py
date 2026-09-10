from __future__ import annotations

from contextlib import AbstractContextManager
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol

from .interfaces import StateRepository


@dataclass(frozen=True)
class ReconciliationLease:
    """Exclusive, fenced ownership of one UNKNOWN execution reconciliation attempt."""

    execution_id: str
    owner_id: str
    fencing_token: int
    acquired_at: datetime
    expires_at: datetime


class ReconciliationLeaseRepository(Protocol):
    def claim_reconciliation_lease(
        self,
        execution_id: str,
        owner_id: str,
        *,
        now: datetime,
        lease_seconds: int,
        allow_terminal_recheck: bool = False,
    ) -> ReconciliationLease | None: ...

    def renew_reconciliation_lease(
        self,
        lease: ReconciliationLease,
        *,
        now: datetime,
        lease_seconds: int,
    ) -> ReconciliationLease: ...

    def release_reconciliation_lease(self, lease: ReconciliationLease) -> bool: ...

    def get_reconciliation_lease(self, execution_id: str) -> ReconciliationLease | None: ...


class FencedReconciliationState(StateRepository, ReconciliationLeaseRepository, Protocol):
    """State repository that atomically fences resolution commits with worker ownership."""

    def resolution_lease(self, lease: ReconciliationLease) -> AbstractContextManager[None]: ...
