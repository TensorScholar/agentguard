from __future__ import annotations

import json
from typing import Any, Mapping

from decisionlock.adapters.protocols.mcp.http_gateway import MCPProtectedHTTPGateway
from decisionlock.adapters.protocols.mcp.http_gateway_types import (
    HTTPExchangeResponse,
    UpstreamTransportError,
)
from decisionlock.adapters.protocols.mcp.modern import (
    CLIENT_CAPABILITIES_META_KEY,
    MODERN_PROTOCOL_PROFILE,
    PROTOCOL_VERSION_META_KEY,
    MCPHTTPServerBinding,
    encode_mcp_header_value,
)
from decisionlock.adapters.reconciliation import (
    MCPHTTPProviderStatusProfile,
    MCPHTTPProviderStatusReconciler,
    SQLiteProviderEffectRepository,
)
from decisionlock.application import DecisionLockService, ProviderBoundExecutionReconciler
from decisionlock.domain import (
    Effect,
    EvidenceTrustLevel,
    ExecutionState,
    Principal,
    ProvenanceLabel,
    ReconciliationStatus,
)
from decisionlock.domain.policy import (
    ActionMatcher,
    PolicyDefaults,
    PolicyDocument,
    PolicyMetadata,
    PolicyRule,
    ProvenanceMatcher,
)
from decisionlock.engine.provider_contracts import external_effect_binding_digest


def _policy() -> PolicyDocument:
    return PolicyDocument(
        metadata=PolicyMetadata(id="phase6d", revision=1),
        defaults=PolicyDefaults(),
        rules=(
            PolicyRule(
                id="allow-read",
                priority=100,
                effect=Effect.ALLOW,
                action=ActionMatcher(tools=frozenset({"read_file"})),
                provenance=ProvenanceMatcher(contains_any=frozenset({ProvenanceLabel.UNVERIFIED})),
            ),
        ),
    )


def _message() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 77,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "README.md"},
            "_meta": {
                PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_PROFILE,
                CLIENT_CAPABILITIES_META_KEY: {},
            },
        },
    }


def _headers(message: dict[str, Any]) -> dict[str, str]:
    return {
        "content-type": "application/json",
        "mcp-protocol-version": MODERN_PROTOCOL_PROFILE,
        "mcp-method": "tools/call",
        "mcp-name": encode_mcp_header_value(str(message["params"]["name"])),
    }


STATUS_SCHEMA = {
    "inputSchema": {
        "type": "object",
        "properties": {"requestId": {"type": "string"}},
        "required": ["requestId"],
    }
}


class AmbiguousThenStatusSender:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.original_execution_id: str | None = None
        self.status_value = "succeeded"

    def send(self, body: bytes, headers: Mapping[str, str]) -> HTTPExchangeResponse:
        del headers
        message = json.loads(body)
        self.calls.append(message)
        if message["method"] == "tools/list":
            response = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "tools": [
                        {
                            "name": "read_file",
                            "inputSchema": {
                                "type": "object",
                                "properties": {"path": {"type": "string"}},
                            },
                        }
                    ]
                },
            }
            return HTTPExchangeResponse(
                200,
                {"content-type": "application/json"},
                json.dumps(response).encode(),
            )
        assert message["method"] == "tools/call"
        name = message["params"]["name"]
        if name == "read_file":
            self.original_execution_id = str(message["id"])
            raise UpstreamTransportError("connection dropped after provider may have accepted")
        assert name == "operation_status"
        assert self.original_execution_id is not None
        assert message["params"]["arguments"]["requestId"] == self.original_execution_id
        response = {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "structuredContent": {
                    "status": self.status_value,
                    "providerOperationId": "provider-op-991",
                }
            },
        }
        return HTTPExchangeResponse(
            200,
            {"content-type": "application/json"},
            json.dumps(response).encode(),
        )


def test_ambiguous_mcp_dispatch_reconciles_from_exact_durable_binding(
    tmp_path, signer, verifier, state
) -> None:
    server_binding = MCPHTTPServerBinding.for_url("filesystem", "http://127.0.0.1:9010/mcp")
    provider_effects = SQLiteProviderEffectRepository(tmp_path / "provider-effects.sqlite")
    sender = AmbiguousThenStatusSender()
    service = DecisionLockService(signer, verifier, state)
    gateway = MCPProtectedHTTPGateway(
        service,
        _policy(),
        Principal(
            agent_id="agent",
            workload_id="mcp-http",
            tenant_id="tenant",
            identity_verified=False,
        ),
        server_binding,
        sender,
        provider_effect_repository=provider_effects,
    )

    message = _message()
    response = gateway.handle(json.dumps(message).encode(), _headers(message))
    payload = json.loads(response.body)
    assert "unknown" in payload["error"]["message"]

    records = state.list_executions()
    assert len(records) == 1
    execution = records[0]
    assert execution.state == ExecutionState.UNKNOWN
    assert sender.original_execution_id == execution.execution_id

    effect = provider_effects.get_external_effect_binding(execution.execution_id)
    assert effect is not None
    assert effect.attempt.execution_id == execution.execution_id
    assert effect.attempt.started_at == execution.dispatching_at
    assert effect.idempotency.replay_disposition.value == "reconcile_before_retry"

    status_reconciler = MCPHTTPProviderStatusReconciler(
        binding=server_binding,
        provider_identity=effect.provider,
        sender=sender,
        profile=MCPHTTPProviderStatusProfile(
            status_tool="operation_status",
            status_tool_schema=STATUS_SCHEMA,
        ),
    )
    resolution = service.reconcile_execution(
        execution.execution_id,
        ProviderBoundExecutionReconciler(provider_effects, status_reconciler),
    )

    assert resolution.status == ReconciliationStatus.CONFIRMED_SUCCEEDED
    assert resolution.trust_level == EvidenceTrustLevel.PROVIDER_VERIFIED
    assert state.get_execution(execution.execution_id).state == ExecutionState.UNKNOWN  # type: ignore[union-attr]
    evidence = provider_effects.list_provider_reconciliation_evidence(
        external_effect_binding_digest(effect)
    )
    assert len(evidence) == 1
    assert evidence[0].status == ReconciliationStatus.CONFIRMED_SUCCEEDED
    assert evidence[0].provider_operation_id_digest is not None
    assert [call["params"]["name"] for call in sender.calls if call["method"] == "tools/call"] == [
        "read_file",
        "operation_status",
    ]


def test_opposite_provider_confirmations_promote_core_resolution_to_conflict(
    tmp_path, signer, verifier, state
) -> None:
    server_binding = MCPHTTPServerBinding.for_url("filesystem", "http://127.0.0.1:9010/mcp")
    provider_effects = SQLiteProviderEffectRepository(tmp_path / "provider-effects.sqlite")
    sender = AmbiguousThenStatusSender()
    service = DecisionLockService(signer, verifier, state)
    gateway = MCPProtectedHTTPGateway(
        service,
        _policy(),
        Principal(agent_id="agent", workload_id="mcp-http", tenant_id="tenant"),
        server_binding,
        sender,
        provider_effect_repository=provider_effects,
    )
    message = _message()
    gateway.handle(json.dumps(message).encode(), _headers(message))
    execution = state.list_executions()[0]
    effect = provider_effects.get_external_effect_binding(execution.execution_id)
    assert effect is not None
    profile = MCPHTTPProviderStatusProfile(
        status_tool="operation_status",
        status_tool_schema=STATUS_SCHEMA,
    )
    reconciler = ProviderBoundExecutionReconciler(
        provider_effects,
        MCPHTTPProviderStatusReconciler(
            binding=server_binding,
            provider_identity=effect.provider,
            sender=sender,
            profile=profile,
        ),
    )

    first = service.reconcile_execution(execution.execution_id, reconciler)
    assert first.status == ReconciliationStatus.CONFIRMED_SUCCEEDED

    sender.status_value = "failed"
    second = service.reconcile_execution(execution.execution_id, reconciler)
    assert second.status == ReconciliationStatus.CONFLICT
    assert second.trust_level == EvidenceTrustLevel.DECISIONLOCK_SIGNED
    assert second.error_code == "reconciliation.conflicting_evidence"
    assert (
        len(
            provider_effects.list_provider_reconciliation_evidence(
                external_effect_binding_digest(effect)
            )
        )
        == 2
    )


class BindingFailureRepository:
    def store_external_effect_binding(self, execution_id, binding, recorded_at) -> None:
        del execution_id, binding, recorded_at
        raise RuntimeError("disk unavailable")

    def get_external_effect_binding(self, execution_id):
        del execution_id
        return None

    def record_provider_reconciliation_evidence(self, evidence, recorded_at) -> None:
        del evidence, recorded_at

    def list_provider_reconciliation_evidence(self, binding_digest):
        del binding_digest
        return ()


def test_binding_persistence_failure_blocks_side_effecting_provider_send(
    signer, verifier, state
) -> None:
    server_binding = MCPHTTPServerBinding.for_url("filesystem", "http://127.0.0.1:9010/mcp")
    sender = AmbiguousThenStatusSender()
    service = DecisionLockService(signer, verifier, state)
    gateway = MCPProtectedHTTPGateway(
        service,
        _policy(),
        Principal(agent_id="agent", workload_id="mcp-http", tenant_id="tenant"),
        server_binding,
        sender,
        provider_effect_repository=BindingFailureRepository(),  # type: ignore[arg-type]
    )

    message = _message()
    gateway.handle(json.dumps(message).encode(), _headers(message))

    assert [call["method"] for call in sender.calls] == ["tools/list"]
    execution = state.list_executions()[0]
    assert execution.state == ExecutionState.FAILED
    assert execution.error_code == "provider_binding.persistence_failed"
