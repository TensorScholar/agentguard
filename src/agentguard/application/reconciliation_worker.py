from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from agentguard.domain import ExecutionRecord, ExecutionState, ReconciliationStatus
from agentguard.ports.interfaces import Clock, ExecutionReconciler, ProviderEffectRepository
from agentguard.ports.reconciliation_work import FencedReconciliationState

from .service import AgentGuardService

TERMINAL_RECONCILIATION_STATUSES = frozenset(
    {
        ReconciliationStatus.CONFIRMED_SUCCEEDED,
        ReconciliationStatus.CONFIRMED_FAILED,
        ReconciliationStatus.CONFLICT,
    }
)


@dataclass(frozen=True)
class ReconciliationWorkerConfig:
    owner_id: str
    lease_seconds: int = 60
    max_items_per_tick: int = 100

    def __post_init__(self) -> None:
        if not self.owner_id.strip():
            raise ValueError("reconciliation.worker_owner_invalid")
        if self.lease_seconds < 1:
            raise ValueError("reconciliation.worker_lease_ttl_invalid")
        if self.max_items_per_tick < 1:
            raise ValueError("reconciliation.worker_max_items_invalid")


@dataclass(frozen=True)
class ReconciliationTickResult:
    scanned: int
    eligible: int
    claimed: int
    reconciled: int
    busy: int
    lease_lost: int
    failed: int


@dataclass(frozen=True)
class ReconciliationWorkerHealth:
    owner_id: str
    live: bool
    ready: bool
    last_tick_started_at: datetime | None
    last_tick_completed_at: datetime | None
    last_error: str | None
    consecutive_failed_ticks: int


class ReconciliationWorker:
    """Lease-fenced multi-process worker for durable provider reconciliation."""

    def __init__(
        self,
        *,
        service: AgentGuardService,
        state: FencedReconciliationState,
        provider_effects: ProviderEffectRepository,
        reconciler: ExecutionReconciler,
        clock: Clock,
        config: ReconciliationWorkerConfig,
    ) -> None:
        self.service = service
        self.state = state
        self.provider_effects = provider_effects
        self.reconciler = reconciler
        self.clock = clock
        self.config = config
        self._live = True
        self._ready = False
        self._last_tick_started_at: datetime | None = None
        self._last_tick_completed_at: datetime | None = None
        self._last_error: str | None = None
        self._consecutive_failed_ticks = 0
        self._cursor_id: str | None = None

    @property
    def cursor_id(self) -> str | None:
        return self._cursor_id

    def _rotate_candidates(self, executions: Sequence[ExecutionRecord]) -> list[ExecutionRecord]:
        exec_list = list(executions)
        if not exec_list or self._cursor_id is None:
            return exec_list
        for index, execution in enumerate(exec_list):
            if execution.execution_id == self._cursor_id:
                return exec_list[index + 1 :] + exec_list[: index + 1]
        self._cursor_id = None
        return exec_list

    def probe_readiness(self) -> bool:
        try:
            self.state.list_executions()
        except Exception as exc:
            self._ready = False
            self._last_error = f"{type(exc).__name__}:{exc}"
            return False
        self._ready = True
        return True

    def health(self) -> ReconciliationWorkerHealth:
        return ReconciliationWorkerHealth(
            owner_id=self.config.owner_id,
            live=self._live,
            ready=self._ready,
            last_tick_started_at=self._last_tick_started_at,
            last_tick_completed_at=self._last_tick_completed_at,
            last_error=self._last_error,
            consecutive_failed_ticks=self._consecutive_failed_ticks,
        )

    def mark_stopped(self) -> None:
        self._live = False
        self._ready = False

    def run_once(self) -> ReconciliationTickResult:
        started_at = self.clock.now()
        self._last_tick_started_at = started_at
        scanned = 0
        eligible = 0
        claimed = 0
        reconciled = 0
        busy = 0
        lease_lost = 0
        failed = 0

        try:
            executions = self.state.list_executions()
            self._ready = True
            ordered_executions = self._rotate_candidates(executions)
            for execution in ordered_executions:
                if claimed >= self.config.max_items_per_tick:
                    break
                if execution.state != ExecutionState.UNKNOWN:
                    continue
                latest_resolution = self.state.get_latest_execution_resolution(
                    execution.execution_id
                )
                if (
                    latest_resolution is not None
                    and latest_resolution.status in TERMINAL_RECONCILIATION_STATUSES
                ):
                    continue
                scanned += 1
                if (
                    self.provider_effects.get_external_effect_binding(execution.execution_id)
                    is None
                ):
                    continue
                eligible += 1
                claim_time = self.clock.now()
                lease = self.state.claim_reconciliation_lease(
                    execution.execution_id,
                    self.config.owner_id,
                    now=claim_time,
                    lease_seconds=self.config.lease_seconds,
                )
                if lease is None:
                    busy += 1
                    continue
                claimed += 1
                self._cursor_id = execution.execution_id
                try:
                    current = self.state.get_execution(execution.execution_id)
                    if current is None or current.state != ExecutionState.UNKNOWN:
                        continue
                    with self.state.resolution_lease(lease):
                        self.service.reconcile_execution(execution.execution_id, self.reconciler)
                    reconciled += 1
                except RuntimeError as exc:
                    if str(exc) == "reconciliation.lease_lost":
                        lease_lost += 1
                    else:
                        failed += 1
                        self._last_error = f"{type(exc).__name__}:{exc}"
                finally:
                    self.state.release_reconciliation_lease(lease)
                if claimed >= self.config.max_items_per_tick:
                    break
        except Exception as exc:
            self._ready = False
            self._last_error = f"{type(exc).__name__}:{exc}"
            self._consecutive_failed_ticks += 1
            self._last_tick_completed_at = self.clock.now()
            raise

        completed_at = self.clock.now()
        self._last_tick_completed_at = completed_at
        if failed or lease_lost:
            self._consecutive_failed_ticks += 1
        else:
            self._consecutive_failed_ticks = 0
            self._last_error = None
        return ReconciliationTickResult(
            scanned=scanned,
            eligible=eligible,
            claimed=claimed,
            reconciled=reconciled,
            busy=busy,
            lease_lost=lease_lost,
            failed=failed,
        )
