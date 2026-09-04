from __future__ import annotations

from agentguard.domain import ExecutionStatus, ProtectedExecutionResult, VerifiedExecution
from agentguard.engine.canonical import digest
from agentguard.ports import AmbiguousExecutionError, DefiniteExecutionFailure


class DeterministicFakeExecutor:
    """In-memory protected executor for integration and failure-path testing only."""

    def __init__(
        self,
        *,
        mode: str = "success",
        provider_status: int | None = 200,
        error_code: str | None = None,
    ) -> None:
        if mode not in {"success", "failure", "unknown", "raise_failure", "raise_unknown", "raise"}:
            raise ValueError("unsupported fake executor mode")
        self.mode = mode
        self.provider_status = provider_status
        self.error_code = error_code
        self.calls: list[VerifiedExecution] = []

    def execute(self, verified_execution: VerifiedExecution) -> ProtectedExecutionResult:
        self.calls.append(verified_execution)
        if self.mode == "raise_failure":
            raise DefiniteExecutionFailure(
                self.error_code or "execution.fake_definite_failure",
                provider_status=self.provider_status,
            )
        if self.mode == "raise_unknown":
            raise AmbiguousExecutionError(self.error_code or "execution.fake_ambiguous")
        if self.mode == "raise":
            raise RuntimeError("synthetic unclassified executor exception")
        if self.mode == "failure":
            return ProtectedExecutionResult(
                status=ExecutionStatus.FAILURE,
                provider_status=self.provider_status,
                error_code=self.error_code or "execution.fake_failure",
            )
        if self.mode == "unknown":
            return ProtectedExecutionResult(
                status=ExecutionStatus.UNKNOWN,
                provider_status=self.provider_status,
                error_code=self.error_code or "execution.fake_unknown",
            )
        return ProtectedExecutionResult(
            status=ExecutionStatus.SUCCESS,
            provider_status=self.provider_status,
            result_digest=digest(
                {
                    "executor": "deterministic-fake",
                    "execution_id": verified_execution.execution_id,
                    "intent_digest": verified_execution.intent_digest,
                }
            ),
        )
