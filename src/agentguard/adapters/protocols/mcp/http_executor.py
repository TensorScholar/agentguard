from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from agentguard.domain import (
    ExecutionAttemptIdentity,
    ExecutionState,
    ExecutionStatus,
    ExternalEffectBinding,
    ExternalOperationIdentity,
    IdempotencyBinding,
    ProtectedExecutionResult,
    ProviderIdentity,
    VerifiedExecution,
)
from agentguard.engine.canonical import digest
from agentguard.engine.provider_contracts import credential_binding_from_verified_authority
from agentguard.ports import (
    AmbiguousExecutionError,
    CredentialMaterialResolver,
    DefiniteExecutionFailure,
    ExecutionRepository,
    ProviderEffectRepository,
)

from .http_gateway_types import HTTPUpstreamSender, UpstreamTransportError
from .jsonrpc import encode_message
from .modern import (
    MODERN_PROTOCOL_PROFILE,
    MCPHTTPServerBinding,
    ModernRequestEnvelope,
    canonical_standard_headers,
    parameter_headers_for_call,
)


class MCPHTTPProtectedExecutor:
    def __init__(
        self,
        *,
        binding: MCPHTTPServerBinding,
        sender: HTTPUpstreamSender,
        envelope: ModernRequestEnvelope,
        tool_schema: dict[str, Any],
        provider_identity: ProviderIdentity | None = None,
        credential_resolver: CredentialMaterialResolver | None = None,
        effect_repository: ProviderEffectRepository | None = None,
        execution_repository: ExecutionRepository | None = None,
    ) -> None:
        if (effect_repository is None) != (execution_repository is None):
            raise ValueError(
                "provider effect and execution repositories must be configured together"
            )
        self.binding = binding
        self.sender = sender
        self.envelope = envelope
        self.tool_schema = tool_schema
        self.provider_identity = provider_identity
        self.credential_resolver = credential_resolver
        self.effect_repository = effect_repository
        self.execution_repository = execution_repository
        self.supports_brokered_credentials = credential_resolver is not None
        self.response: dict[str, Any] | None = None
        self.effect_binding: ExternalEffectBinding | None = None

    def execute(self, verified_execution: VerifiedExecution) -> ProtectedExecutionResult:
        self._validate_binding(verified_execution)
        if digest(verified_execution.intent.tool_schema) != digest(self.tool_schema):
            raise DefiniteExecutionFailure("mcp_http.tool_schema_changed_at_dispatch")
        downstream = {
            "jsonrpc": "2.0",
            "id": verified_execution.execution_id,
            "method": "tools/call",
            "params": {
                "name": verified_execution.intent.action.tool,
                "arguments": verified_execution.intent.arguments,
                "_meta": self.envelope.as_meta(),
            },
        }
        headers = canonical_standard_headers(downstream)
        headers.update(parameter_headers_for_call(downstream, self.tool_schema))
        self._persist_external_effect_binding(verified_execution)
        self._inject_brokered_credential(verified_execution, headers)
        try:
            response = self.sender.send(encode_message(downstream), headers)
        except UpstreamTransportError as exc:
            raise AmbiguousExecutionError("mcp_http.upstream_transport_ambiguous") from exc

        content_type = response.headers.get("content-type", "").lower()
        if "text/event-stream" in content_type:
            raise AmbiguousExecutionError("mcp_http.protected_sse_outcome_ambiguous")
        try:
            parsed = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise AmbiguousExecutionError("mcp_http.malformed_provider_response") from exc
        if not isinstance(parsed, dict):
            raise AmbiguousExecutionError("mcp_http.malformed_provider_response")
        if parsed.get("id") != verified_execution.execution_id:
            raise AmbiguousExecutionError("mcp_http.response_id_mismatch")
        self.response = parsed
        result_digest = digest(parsed)
        if "error" in parsed:
            error = parsed.get("error")
            provider_status = error.get("code") if isinstance(error, dict) else None
            return ProtectedExecutionResult(
                status=ExecutionStatus.FAILURE,
                provider_status=provider_status if isinstance(provider_status, int) else None,
                result_digest=result_digest,
                error_code="mcp_http.jsonrpc_error",
            )
        result = parsed.get("result")
        if not isinstance(result, dict):
            raise AmbiguousExecutionError("mcp_http.malformed_correlated_response")
        if result.get("resultType") == "input_required":
            # The Phase-5 execution ledger has no durable PENDING/MRTR state. Marking this as
            # SUCCESS would be false evidence, while retrying may duplicate a partial effect.
            raise AmbiguousExecutionError("mcp_http.mrtr_input_required_outcome_unknown")
        if result.get("isError") is True:
            return ProtectedExecutionResult(
                status=ExecutionStatus.FAILURE,
                provider_status=response.status_code,
                result_digest=result_digest,
                error_code="mcp_http.tool_result_error",
            )
        return ProtectedExecutionResult(
            status=ExecutionStatus.SUCCESS,
            provider_status=response.status_code,
            result_digest=result_digest,
        )

    def _persist_external_effect_binding(self, verified: VerifiedExecution) -> None:
        if self.effect_repository is None or self.execution_repository is None:
            return
        record = self.execution_repository.get_execution(verified.execution_id)
        if record is None:
            raise DefiniteExecutionFailure("provider_binding.execution_record_missing")
        if record.state != ExecutionState.DISPATCHING or record.dispatching_at is None:
            raise DefiniteExecutionFailure("provider_binding.execution_not_dispatching")
        if self.provider_identity is None:
            raise DefiniteExecutionFailure("mcp_http.provider_identity_missing")
        credential = (
            credential_binding_from_verified_authority(verified.credential_authority)
            if verified.credential_authority is not None
            else None
        )
        operation_seed = {
            "execution_id": verified.execution_id,
            "decision_id": verified.decision_id,
        }
        binding = ExternalEffectBinding(
            decision_id=verified.decision_id,
            intent_digest=verified.intent_digest,
            action_digest=digest(verified.intent.action),
            resource_digest=(
                digest(verified.intent.resource) if verified.intent.resource is not None else None
            ),
            arguments_digest=digest(verified.intent.arguments),
            provider=self.provider_identity,
            operation=ExternalOperationIdentity(
                operation_id="op_" + digest(operation_seed)[7:39],
                operation_kind="mcp.tools/call",
                operation_name=verified.intent.action.tool,
            ),
            credential=credential,
            attempt=ExecutionAttemptIdentity(
                execution_id=verified.execution_id,
                attempt_id="attempt_" + digest({**operation_seed, "attempt_number": 1})[7:39],
                attempt_number=1,
                started_at=record.dispatching_at,
            ),
            idempotency=IdempotencyBinding(),
        )
        try:
            self.effect_repository.store_external_effect_binding(
                verified.execution_id,
                binding,
                datetime.now(UTC),
            )
        except (ValueError, RuntimeError) as exc:
            raise DefiniteExecutionFailure("provider_binding.persistence_failed") from exc
        self.effect_binding = binding

    def _inject_brokered_credential(
        self, verified: VerifiedExecution, headers: dict[str, str]
    ) -> None:
        authority = verified.credential_authority
        if authority is None:
            return
        if authority.mode != "brokered_execution":
            # VerifiedExecution deliberately contains no opaque credential handle. Such grants
            # cannot be reconstructed safely at this boundary.
            raise DefiniteExecutionFailure("mcp_http.opaque_credential_not_dispatchable")
        if self.credential_resolver is None or self.provider_identity is None:
            raise DefiniteExecutionFailure("credential.material_resolver_unavailable")
        try:
            material = self.credential_resolver.resolve(authority, self.provider_identity)
        except (ValueError, RuntimeError) as exc:
            raise DefiniteExecutionFailure("credential.material_resolution_failed") from exc
        normalized = {name.lower() for name in headers}
        if material.header_name.lower() in normalized:
            raise DefiniteExecutionFailure("credential.header_collision")
        headers[material.header_name] = material.header_value

    def _validate_binding(self, verified: VerifiedExecution) -> None:
        intent = verified.intent
        resource = intent.resource
        if intent.action.protocol != "mcp" or intent.action.operation != "call":
            raise DefiniteExecutionFailure("mcp_http.execution_binding_invalid")
        if intent.action.server != self.binding.server_id:
            raise DefiniteExecutionFailure("mcp_http.server_binding_mismatch")
        if resource is None or resource.type != "mcp_http_server":
            raise DefiniteExecutionFailure("mcp_http.resource_binding_missing")
        if resource.id != self.binding.server_id:
            raise DefiniteExecutionFailure("mcp_http.resource_server_mismatch")
        attributes = resource.attributes
        if attributes.get("transport") != "streamable_http":
            raise DefiniteExecutionFailure("mcp_http.transport_binding_mismatch")
        if attributes.get("protocol_profile") != MODERN_PROTOCOL_PROFILE:
            raise DefiniteExecutionFailure("mcp_http.protocol_profile_binding_mismatch")
        if attributes.get("endpoint_digest") != self.binding.endpoint_digest:
            raise DefiniteExecutionFailure("mcp_http.endpoint_binding_mismatch")
        if attributes.get("server_binding_digest") != self.binding.binding_digest:
            raise DefiniteExecutionFailure("mcp_http.server_binding_digest_mismatch")
        if attributes.get("request_envelope_digest") != digest(self.envelope.as_meta()):
            raise DefiniteExecutionFailure("mcp_http.request_envelope_binding_mismatch")
        if self.provider_identity is None:
            raise DefiniteExecutionFailure("mcp_http.provider_identity_missing")
        if attributes.get("provider_identity_digest") != digest(self.provider_identity):
            raise DefiniteExecutionFailure("mcp_http.provider_identity_binding_mismatch")
