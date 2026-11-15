from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import pytest

from decisionlock.adapters.protocols.mcp.http_gateway_types import (
    HTTPExchangeResponse,
    UpstreamTransportError,
)
from decisionlock.adapters.protocols.mcp.modern import MCPHTTPServerBinding
from decisionlock.adapters.reconciliation import (
    MCPHTTPProviderStatusProfile,
    MCPHTTPProviderStatusReconciler,
    ProviderReconciliationStoreError,
    SQLiteProviderEffectRepository,
)
from decisionlock.application import ProviderBoundExecutionReconciler, ProviderReconciliationError
from decisionlock.domain import (
    EvidenceTrustLevel,
    ExecutionAttemptIdentity,
    ExecutionRecord,
    ExecutionState,
    ExternalEffectBinding,
    ExternalOperationIdentity,
    IdempotencyBinding,
    ProviderIdentity,
    ProviderReconciliationEvidence,
    ReconciliationStatus,
)
from decisionlock.engine.canonical import digest
from decisionlock.engine.provider_contracts import external_effect_binding_digest

NOW = datetime(2026, 9, 2, 12, 0, tzinfo=UTC)


def _binding(*, execution_id: str = "exec_1") -> ExternalEffectBinding:
    provider = ProviderIdentity(
        provider_id="filesystem",
        endpoint_digest="sha256:" + "1" * 64,
    )
    return ExternalEffectBinding(
        decision_id="decision_1",
        intent_digest="sha256:" + "2" * 64,
        action_digest="sha256:" + "3" * 64,
        resource_digest="sha256:" + "4" * 64,
        arguments_digest="sha256:" + "5" * 64,
        provider=provider,
        operation=ExternalOperationIdentity(
            operation_id="operation_1",
            operation_kind="mcp.tools/call",
            operation_name="read_file",
        ),
        attempt=ExecutionAttemptIdentity(
            execution_id=execution_id,
            attempt_id="attempt_1",
            attempt_number=1,
            started_at=NOW,
        ),
        idempotency=IdempotencyBinding(),
    )


def _execution(binding: ExternalEffectBinding) -> ExecutionRecord:
    return ExecutionRecord(
        execution_id=binding.attempt.execution_id,
        decision_id=binding.decision_id,
        trace_id="trace_1",
        request_id="request_1",
        intent_digest=binding.intent_digest,
        authority_digest="sha256:" + "6" * 64,
        state=ExecutionState.UNKNOWN,
        reserved_at=NOW - timedelta(seconds=1),
        dispatching_at=NOW,
        completed_at=NOW + timedelta(seconds=1),
        error_code="execution.outcome_ambiguous",
    )


def _evidence(
    binding: ExternalEffectBinding,
    *,
    status: ReconciliationStatus = ReconciliationStatus.CONFIRMED_SUCCEEDED,
    evidence_digest: str | None = None,
) -> ProviderReconciliationEvidence:
    return ProviderReconciliationEvidence(
        binding_digest=external_effect_binding_digest(binding),
        source="provider-status",
        evidence_digest=evidence_digest or ("sha256:" + "7" * 64),
        trust_level=EvidenceTrustLevel.PROVIDER_VERIFIED,
        observed_at=NOW + timedelta(seconds=2),
        provider_operation_id_digest="sha256:" + "8" * 64,
        provider_status=200,
        status=status,
    )


def _http_binding() -> MCPHTTPServerBinding:
    return MCPHTTPServerBinding.for_url("filesystem", "http://127.0.0.1:9010/mcp")


def _http_effect() -> ExternalEffectBinding:
    http_binding = _http_binding()
    return _binding().model_copy(
        update={
            "provider": ProviderIdentity(
                provider_id="filesystem",
                endpoint_digest=http_binding.endpoint_digest,
            )
        }
    )


def _status_profile() -> MCPHTTPProviderStatusProfile:
    return MCPHTTPProviderStatusProfile(
        status_tool="operation_status",
        status_tool_schema={
            "inputSchema": {
                "type": "object",
                "properties": {"requestId": {"type": "string"}},
            }
        },
    )


def test_provider_effect_store_round_trips_binding_and_evidence(tmp_path) -> None:
    repository = SQLiteProviderEffectRepository(tmp_path / "provider.sqlite")
    binding = _binding()
    repository.store_external_effect_binding(binding.attempt.execution_id, binding, NOW)
    repository.store_external_effect_binding(binding.attempt.execution_id, binding, NOW)

    assert repository.get_external_effect_binding(binding.attempt.execution_id) == binding

    evidence = _evidence(binding)
    repository.record_provider_reconciliation_evidence(evidence, NOW + timedelta(seconds=3))
    repository.record_provider_reconciliation_evidence(evidence, NOW + timedelta(seconds=4))
    assert repository.list_provider_reconciliation_evidence(
        external_effect_binding_digest(binding)
    ) == (evidence,)


def test_provider_effect_store_rejects_conflicting_binding_and_orphan_evidence(tmp_path) -> None:
    repository = SQLiteProviderEffectRepository(tmp_path / "provider.sqlite")
    binding = _binding()
    repository.store_external_effect_binding(binding.attempt.execution_id, binding, NOW)
    conflicting = binding.model_copy(update={"arguments_digest": "sha256:" + "9" * 64})
    with pytest.raises(
        ProviderReconciliationStoreError,
        match="provider_binding.execution_conflict",
    ):
        repository.store_external_effect_binding(binding.attempt.execution_id, conflicting, NOW)

    other_binding = _binding(execution_id="exec_other")
    with pytest.raises(
        ProviderReconciliationStoreError,
        match="provider_evidence.binding_missing",
    ):
        repository.record_provider_reconciliation_evidence(
            _evidence(other_binding), NOW + timedelta(seconds=1)
        )


class StaticProviderReconciler:
    def __init__(self, evidence: ProviderReconciliationEvidence) -> None:
        self.evidence = evidence
        self.calls = 0

    def reconcile(self, binding: ExternalEffectBinding) -> ProviderReconciliationEvidence:
        self.calls += 1
        return self.evidence


def test_provider_bound_adapter_requires_exact_binding_and_persists_evidence(tmp_path) -> None:
    repository = SQLiteProviderEffectRepository(tmp_path / "provider.sqlite")
    binding = _binding()
    repository.store_external_effect_binding(binding.attempt.execution_id, binding, NOW)
    evidence = _evidence(binding)
    provider = StaticProviderReconciler(evidence)
    reconciler = ProviderBoundExecutionReconciler(repository, provider)

    generic = reconciler.reconcile(_execution(binding))

    assert provider.calls == 1
    assert generic.status == ReconciliationStatus.CONFIRMED_SUCCEEDED
    assert generic.trust_level == EvidenceTrustLevel.PROVIDER_VERIFIED
    assert generic.evidence_digest == evidence.evidence_digest
    assert repository.list_provider_reconciliation_evidence(
        external_effect_binding_digest(binding)
    ) == (evidence,)

    mismatched = _execution(binding).model_copy(update={"decision_id": "wrong"})
    with pytest.raises(
        ProviderReconciliationError,
        match="provider_reconciliation.decision_binding_mismatch",
    ):
        reconciler.reconcile(mismatched)


def test_provider_bound_adapter_rejects_mismatched_or_predispatch_evidence(tmp_path) -> None:
    repository = SQLiteProviderEffectRepository(tmp_path / "provider.sqlite")
    binding = _binding()
    repository.store_external_effect_binding(binding.attempt.execution_id, binding, NOW)

    wrong_binding = binding.model_copy(update={"arguments_digest": "sha256:" + "a" * 64})
    wrong_evidence = _evidence(wrong_binding)
    with pytest.raises(ProviderReconciliationError, match="provider_evidence.binding_mismatch"):
        ProviderBoundExecutionReconciler(
            repository, StaticProviderReconciler(wrong_evidence)
        ).reconcile(_execution(binding))

    predates = _evidence(binding).model_copy(update={"observed_at": NOW - timedelta(seconds=1)})
    with pytest.raises(ProviderReconciliationError, match="provider_evidence.predates_dispatch"):
        ProviderBoundExecutionReconciler(repository, StaticProviderReconciler(predates)).reconcile(
            _execution(binding)
        )


def test_provider_bound_adapter_fail_closed_execution_correlations(tmp_path) -> None:
    repository = SQLiteProviderEffectRepository(tmp_path / "provider.sqlite")
    binding = _binding()
    reconciler = ProviderBoundExecutionReconciler(
        repository, StaticProviderReconciler(_evidence(binding))
    )

    with pytest.raises(
        ProviderReconciliationError, match="provider_reconciliation.binding_missing"
    ):
        reconciler.reconcile(_execution(binding))

    repository.store_external_effect_binding(binding.attempt.execution_id, binding, NOW)
    with pytest.raises(
        ProviderReconciliationError,
        match="provider_reconciliation.intent_binding_mismatch",
    ):
        reconciler.reconcile(
            _execution(binding).model_copy(update={"intent_digest": "sha256:" + "f" * 64})
        )
    with pytest.raises(
        ProviderReconciliationError,
        match="provider_reconciliation.dispatch_time_missing",
    ):
        reconciler.reconcile(_execution(binding).model_copy(update={"dispatching_at": None}))
    with pytest.raises(
        ProviderReconciliationError,
        match="provider_reconciliation.attempt_time_mismatch",
    ):
        reconciler.reconcile(
            _execution(binding).model_copy(update={"dispatching_at": NOW + timedelta(seconds=1)})
        )

    conflict = _evidence(binding, status=ReconciliationStatus.CONFLICT)
    with pytest.raises(
        ProviderReconciliationError,
        match="reconciliation.adapter_cannot_assert_conflict",
    ):
        ProviderBoundExecutionReconciler(repository, StaticProviderReconciler(conflict)).reconcile(
            _execution(binding)
        )


class DownSender:
    def send(self, body: bytes, headers) -> object:
        del body, headers
        raise UpstreamTransportError("down")


class ScriptedStatusSender:
    def __init__(self, mode: str) -> None:
        self.mode = mode

    def send(self, body: bytes, headers) -> HTTPExchangeResponse:
        del headers
        message = json.loads(body)
        if self.mode == "http_error":
            return HTTPExchangeResponse(503, {"content-type": "application/json"}, b"{}")
        if self.mode == "invalid_json":
            return HTTPExchangeResponse(200, {"content-type": "application/json"}, b"{")
        if self.mode == "wrong_id":
            payload = {"jsonrpc": "2.0", "id": "wrong", "result": {}}
        elif self.mode == "rpc_error":
            payload = {"jsonrpc": "2.0", "id": message["id"], "error": {"code": -1}}
        elif self.mode == "invalid_result":
            payload = {"jsonrpc": "2.0", "id": message["id"], "result": []}
        elif self.mode == "missing_structured":
            payload = {"jsonrpc": "2.0", "id": message["id"], "result": {}}
        elif self.mode == "missing_state":
            payload = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"structuredContent": {}},
            }
        elif self.mode == "invalid_operation_id":
            payload = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"structuredContent": {"status": "completed", "providerOperationId": 42}},
            }
        else:
            payload = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "structuredContent": {
                        "status": self.mode,
                        "providerOperationId": "provider-op-1",
                    }
                },
            }
        return HTTPExchangeResponse(
            200,
            {"content-type": "application/json"},
            json.dumps(payload).encode(),
        )


def _run_status(mode: str) -> ProviderReconciliationEvidence:
    binding = _http_effect()
    return MCPHTTPProviderStatusReconciler(
        binding=_http_binding(),
        provider_identity=binding.provider,
        sender=ScriptedStatusSender(mode),
        profile=_status_profile(),
    ).reconcile(binding)


def test_mcp_provider_status_transport_failure_stays_unknown() -> None:
    binding = _http_effect()
    evidence = MCPHTTPProviderStatusReconciler(
        binding=_http_binding(),
        provider_identity=binding.provider,
        sender=DownSender(),  # type: ignore[arg-type]
        profile=_status_profile(),
    ).reconcile(binding)

    assert evidence.status == ReconciliationStatus.STILL_UNKNOWN
    assert evidence.trust_level == EvidenceTrustLevel.DECISIONLOCK_SIGNED
    assert evidence.binding_digest == external_effect_binding_digest(binding)
    assert evidence.error_code == "provider_status.transport_unavailable"
    assert evidence.evidence_digest == digest(
        {
            "binding_digest": digest(binding),
            "status_tool": "operation_status",
            "error": "transport_unavailable",
            "observed_at": evidence.observed_at,
        }
    )


@pytest.mark.parametrize(
    ("mode", "error_code"),
    [
        ("http_error", "provider_status.http_error"),
        ("invalid_json", "provider_status.response_invalid"),
        ("wrong_id", "provider_status.protocol_error"),
        ("rpc_error", "provider_status.protocol_error"),
        ("invalid_result", "provider_status.result_invalid"),
        ("missing_structured", "provider_status.structured_content_required"),
        ("missing_state", "provider_status.state_missing"),
        ("invalid_operation_id", "provider_status.operation_id_invalid"),
    ],
)
def test_mcp_provider_status_malformed_evidence_never_confirms(mode: str, error_code: str) -> None:
    evidence = _run_status(mode)
    assert evidence.status == ReconciliationStatus.STILL_UNKNOWN
    assert evidence.trust_level == EvidenceTrustLevel.DECISIONLOCK_SIGNED
    assert evidence.error_code == error_code


@pytest.mark.parametrize(
    ("mode", "status", "error_code"),
    [
        ("failed", ReconciliationStatus.CONFIRMED_FAILED, None),
        ("running", ReconciliationStatus.STILL_UNKNOWN, None),
        ("unexpected", ReconciliationStatus.STILL_UNKNOWN, "provider_status.state_unrecognized"),
    ],
)
def test_mcp_provider_status_maps_only_registered_states(
    mode: str,
    status: ReconciliationStatus,
    error_code: str | None,
) -> None:
    evidence = _run_status(mode)
    assert evidence.status == status
    assert evidence.trust_level == EvidenceTrustLevel.PROVIDER_VERIFIED
    assert evidence.error_code == error_code
    assert evidence.provider_operation_id_digest == digest("provider-op-1")


def test_mcp_provider_status_rejects_binding_identity_and_operation_mismatch() -> None:
    http_binding = _http_binding()
    binding = _http_effect()
    subject = MCPHTTPProviderStatusReconciler(
        binding=http_binding,
        provider_identity=binding.provider,
        sender=DownSender(),  # type: ignore[arg-type]
        profile=_status_profile(),
    )
    wrong_provider = binding.model_copy(
        update={
            "provider": ProviderIdentity(
                provider_id="other",
                endpoint_digest=http_binding.endpoint_digest,
            )
        }
    )
    with pytest.raises(ValueError, match="provider_reconciliation.provider_identity_mismatch"):
        subject.reconcile(wrong_provider)

    endpoint_subject = MCPHTTPProviderStatusReconciler(
        binding=http_binding,
        provider_identity=ProviderIdentity(
            provider_id="filesystem",
            endpoint_digest="sha256:" + "d" * 64,
        ),
        sender=DownSender(),  # type: ignore[arg-type]
        profile=_status_profile(),
    )
    endpoint_binding = binding.model_copy(update={"provider": endpoint_subject.provider_identity})
    with pytest.raises(ValueError, match="provider_reconciliation.endpoint_binding_mismatch"):
        endpoint_subject.reconcile(endpoint_binding)

    unsupported = binding.model_copy(
        update={
            "operation": binding.operation.model_copy(update={"operation_kind": "provider.custom"})
        }
    )
    with pytest.raises(ValueError, match="provider_reconciliation.operation_kind_unsupported"):
        subject.reconcile(unsupported)


@pytest.mark.parametrize(
    "kwargs",
    [
        {"status_tool": ""},
        {"provider_operation_id_field": ""},
        {"succeeded_values": frozenset()},
        {"succeeded_values": frozenset({"same"}), "failed_values": frozenset({"same"})},
        {"succeeded_values": frozenset({"same"}), "pending_values": frozenset({"same"})},
    ],
)
def test_mcp_provider_status_profile_rejects_ambiguous_contracts(kwargs: dict[str, object]) -> None:
    base: dict[str, object] = {
        "status_tool": "operation_status",
        "status_tool_schema": {"inputSchema": {}},
    }
    base.update(kwargs)
    with pytest.raises(ValueError):
        MCPHTTPProviderStatusProfile(**base)  # type: ignore[arg-type]
