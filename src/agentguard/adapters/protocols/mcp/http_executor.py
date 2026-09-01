from __future__ import annotations

import json
from typing import Any

from agentguard.domain import ExecutionStatus, ProtectedExecutionResult, VerifiedExecution
from agentguard.engine.canonical import digest
from agentguard.ports import AmbiguousExecutionError, DefiniteExecutionFailure

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
    ) -> None:
        self.binding = binding
        self.sender = sender
        self.envelope = envelope
        self.tool_schema = tool_schema
        self.response: dict[str, Any] | None = None

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
