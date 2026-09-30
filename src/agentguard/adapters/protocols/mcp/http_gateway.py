from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any, Mapping
from uuid import uuid4

from agentguard.application import AgentGuardService, ExecutionPersistenceError
from agentguard.domain import (
    CredentialRequest,
    Effect,
    ExecutionStatus,
    PolicyDocument,
    Principal,
    ProvenanceLabel,
    ProviderIdentity,
    Resource,
)
from agentguard.engine.canonical import digest
from agentguard.ports import (
    CredentialBroker,
    CredentialMaterialResolver,
    ProviderEffectRepository,
)

from .http_executor import MCPHTTPProtectedExecutor
from .http_gateway_types import (
    GatewayResponse,
    HTTPExchangeResponse,
    HTTPUpstreamSender,
    UpstreamTransportError,
)
from .intent import intent_from_tools_call
from .jsonrpc import encode_message, error_response
from .modern import (
    MODERN_PROTOCOL_PROFILE,
    MCPHTTPServerBinding,
    ModernMCPValidationError,
    ModernRequestEnvelope,
    canonical_standard_headers,
    parse_json_object,
    validate_modern_request_headers,
    validate_parameter_headers,
)
from .protected import (
    PROTECTED_APPROVAL_REQUIRED,
    PROTECTED_EXECUTION_ERROR,
    PROTECTED_OUTCOME_UNKNOWN,
    PROTECTED_POLICY_DENIED,
    PROTECTED_REQUEST_REJECTED,
    PROTECTED_SCHEMA_UNAVAILABLE,
)

SAFE_PASSTHROUGH_METHODS = frozenset(
    {
        "server/discover",
        "ping",
        "tools/list",
        "prompts/list",
        "prompts/get",
        "resources/list",
        "resources/templates/list",
        "resources/read",
        "completion/complete",
    }
)
STREAMING_PASSTHROUGH_METHODS = frozenset({"subscriptions/listen"})


class MCPProtectedHTTPGateway:
    """Stateless protected MCP 2026-07-28 gateway core.

    Each HTTP request is independently validated. Protected tools/call requests refresh their tool
    schema from the configured upstream before authorization, canonicalize all MCP routing and
    x-mcp-header fields, and dispatch only through AgentGuard's one-winner protected executor.
    Credential-bound calls receive brokered provider material only after authorization and only at
    the final protected dispatch boundary.
    """

    def __init__(
        self,
        service: AgentGuardService,
        policy: PolicyDocument,
        principal: Principal,
        binding: MCPHTTPServerBinding,
        sender: HTTPUpstreamSender,
        *,
        credential_broker: CredentialBroker | None = None,
        credential_material_resolver: CredentialMaterialResolver | None = None,
        provider_identity: ProviderIdentity | None = None,
        provider_effect_repository: ProviderEffectRepository | None = None,
        max_message_bytes: int = 1_000_000,
        max_schema_pages: int = 32,
        max_schema_tools: int = 4096,
        provenance: tuple[ProvenanceLabel, ...] = (ProvenanceLabel.UNVERIFIED,),
        provenance_verified: bool = False,
    ) -> None:
        if max_message_bytes < 1:
            raise ValueError("max_message_bytes must be greater than zero")
        if max_schema_pages < 1 or max_schema_tools < 1:
            raise ValueError("schema inventory limits must be positive")
        if (credential_broker is None) != (credential_material_resolver is None):
            raise ValueError("credential broker and material resolver must be configured together")
        self.service = service
        self.policy = policy
        self.principal = principal
        self.binding = binding
        self.sender = sender
        self.credential_broker = credential_broker
        self.credential_material_resolver = credential_material_resolver
        self.provider_identity = provider_identity or ProviderIdentity(
            provider_id=binding.server_id,
            tenant_id=principal.tenant_id,
            endpoint_digest=binding.endpoint_digest,
        )
        self.provider_effect_repository = provider_effect_repository
        self.max_message_bytes = max_message_bytes
        self.max_schema_pages = max_schema_pages
        self.max_schema_tools = max_schema_tools
        # Provenance is a property of the deployment's transport, not something the
        # gateway can infer from the wire. The adapter is a TCB boundary and is
        # expected to label it accurately (see docs/threat-model.md). Default stays
        # UNVERIFIED so an unconfigured gateway cannot assert trust it has not
        # established.
        self.provenance = provenance
        self.provenance_verified = provenance_verified

    def handle(self, body: bytes, headers: Mapping[str, str]) -> GatewayResponse:
        try:
            message = parse_json_object(body, max_bytes=self.max_message_bytes)
            envelope = validate_modern_request_headers(message, headers)
        except ModernMCPValidationError as exc:
            return self._error(None, exc.code, exc.reason, status_code=exc.http_status)
        request_id = message.get("id")
        method = message.get("method")
        assert isinstance(method, str)
        if request_id is None:
            return self._error(
                None,
                PROTECTED_REQUEST_REJECTED,
                "AgentGuard modern HTTP endpoint accepts request/response RPCs only",
            )
        if method == "initialize":
            return self._error(
                request_id,
                PROTECTED_REQUEST_REJECTED,
                "initialize is not valid on the pinned MCP 2026-07-28 endpoint",
            )
        if method == "tools/call":
            return self._handle_tools_call(message, headers, envelope)
        if method in STREAMING_PASSTHROUGH_METHODS:
            return self._error(
                request_id,
                PROTECTED_REQUEST_REJECTED,
                "streaming method requires the ASGI Streamable HTTP adapter",
            )
        if method not in SAFE_PASSTHROUGH_METHODS:
            return self._error(
                request_id,
                -32601,
                "method unsupported by AgentGuard protected modern MCP profile",
            )
        return self._forward(message)

    def _handle_tools_call(
        self,
        message: dict[str, Any],
        inbound_headers: Mapping[str, str],
        envelope: ModernRequestEnvelope,
    ) -> GatewayResponse:
        request_id = message.get("id")
        params = message.get("params")
        if not isinstance(params, dict):
            return self._error(request_id, -32602, "invalid tools/call params")
        if "inputResponses" in params or "requestState" in params:
            return self._error(
                request_id,
                PROTECTED_REQUEST_REJECTED,
                "MRTR continuation fields are not yet representable "
                "in the durable execution ledger",
                data={"reason_codes": ["mcp_http.mrtr_not_supported_by_execution_ledger"]},
            )
        tool = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(tool, str) or not tool or not isinstance(arguments, dict):
            return self._error(request_id, -32602, "invalid tools/call")
        try:
            schema = self._fetch_fresh_tool_schema(tool, envelope)
            if schema is not None:
                validate_parameter_headers(message, inbound_headers, schema)
        except ModernMCPValidationError as exc:
            return self._error(request_id, exc.code, exc.reason, status_code=exc.http_status)
        except UpstreamTransportError:
            return self._error(
                request_id,
                PROTECTED_SCHEMA_UNAVAILABLE,
                "trusted upstream tool schema is unavailable",
                data={"reason_codes": ["mcp_http.schema_refresh_failed"]},
                status_code=502,
            )
        if schema is None:
            return self._error(
                request_id,
                PROTECTED_SCHEMA_UNAVAILABLE,
                "trusted upstream tool schema is unavailable",
            )

        resource = Resource(
            type="mcp_http_server",
            id=self.binding.server_id,
            attributes={
                "transport": "streamable_http",
                "protocol_profile": MODERN_PROTOCOL_PROFILE,
                "endpoint_digest": self.binding.endpoint_digest,
                "server_binding_digest": self.binding.binding_digest,
                "request_envelope_digest": digest(envelope.as_meta()),
                "provider_identity_digest": digest(self.provider_identity),
            },
        )
        bound_message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
        try:
            intent = intent_from_tools_call(
                bound_message,
                principal=self.principal,
                server=self.binding.server_id,
                request_id="mcphttpreq_" + uuid4().hex,
                tool_schema=schema,
                resource=resource,
                provenance=self.provenance,
                provenance_verified=self.provenance_verified,
            )
            receipt = self.service.authorize(intent, self.policy)
        except Exception as exc:
            return self._error(
                request_id,
                PROTECTED_EXECUTION_ERROR,
                "authorization failed",
                data={"reason": type(exc).__name__},
            )
        if receipt.effect == Effect.DENY:
            return self._error(
                request_id,
                PROTECTED_POLICY_DENIED,
                "AgentGuard denied tool call",
                data={
                    "decision_id": receipt.decision_id,
                    "reason_codes": list(receipt.reason_codes),
                },
            )
        if receipt.effect == Effect.REQUIRE_APPROVAL:
            return self._error(
                request_id,
                PROTECTED_APPROVAL_REQUIRED,
                "AgentGuard requires approval",
                data={
                    "decision_id": receipt.decision_id,
                    "reason_codes": list(receipt.reason_codes),
                },
            )
        if receipt.staging_requirement is not None and receipt.staging_requirement.required:
            return self._error(
                request_id,
                PROTECTED_REQUEST_REJECTED,
                "staged execution is not exposed through the modern MCP HTTP endpoint",
                data={"decision_id": receipt.decision_id},
            )

        grant = None
        ceiling = receipt.credential_ceiling
        if ceiling is not None:
            if self.credential_broker is None or self.credential_material_resolver is None:
                return self._error(
                    request_id,
                    PROTECTED_EXECUTION_ERROR,
                    "credential authority is unavailable for this protected call",
                    data={"decision_id": receipt.decision_id},
                )
            remaining_seconds = int((receipt.expires_at - datetime.now(UTC)).total_seconds())
            if remaining_seconds < 1:
                return self._error(
                    request_id,
                    PROTECTED_EXECUTION_ERROR,
                    "authorization expired before credential issuance",
                    data={"decision_id": receipt.decision_id},
                )
            credential_request = CredentialRequest(
                request_id="mcpcred_" + uuid4().hex,
                trace_id=receipt.trace_id,
                decision_id=receipt.decision_id,
                audience=ceiling.audience,
                scopes=ceiling.scopes,
                requested_ttl_seconds=min(ceiling.maximum_ttl_seconds, remaining_seconds),
                tenant_id=ceiling.tenant_id,
            )
            try:
                grant = self.service.request_credential(
                    intent,
                    receipt,
                    credential_request,
                    self.credential_broker,
                )
            except Exception as exc:
                # Carry the stable credential reason code (for example
                # credential.profile_unavailable) rather than only the exception
                # class. Every code raised here is a fixed, secret-free identifier,
                # and without it a credential misconfiguration -- most often a
                # --tenant-id that does not match the policy ceiling, or a profile
                # whose scopes do not match -- is indistinguishable.
                return self._error(
                    request_id,
                    PROTECTED_EXECUTION_ERROR,
                    "credential issuance failed",
                    data={
                        "reason": type(exc).__name__,
                        "reason_code": str(exc),
                        "decision_id": receipt.decision_id,
                    },
                )

        executor = MCPHTTPProtectedExecutor(
            binding=self.binding,
            sender=self.sender,
            envelope=envelope,
            tool_schema=schema,
            provider_identity=self.provider_identity,
            credential_resolver=(self.credential_material_resolver if grant is not None else None),
            effect_repository=self.provider_effect_repository,
            execution_repository=(
                self.service.state if self.provider_effect_repository is not None else None
            ),
        )
        try:
            outcome = self.service.execute_protected(
                intent,
                receipt,
                grant,
                executor,
                current_policy=self.policy,
            )
        except ExecutionPersistenceError:
            return self._error(
                request_id,
                PROTECTED_OUTCOME_UNKNOWN,
                "protected HTTP outcome persistence is ambiguous",
                data={"retry_safe": False},
            )
        except Exception as exc:
            return self._error(
                request_id,
                PROTECTED_EXECUTION_ERROR,
                "protected HTTP execution failed",
                data={"reason": type(exc).__name__, "retry_safe": False},
            )
        if outcome.status == ExecutionStatus.UNKNOWN:
            return self._error(
                request_id,
                PROTECTED_OUTCOME_UNKNOWN,
                "protected HTTP outcome is unknown and must not be retried automatically",
                data={"execution_id": outcome.execution_id, "retry_safe": False},
            )
        if executor.response is not None:
            client_response = dict(executor.response)
            client_response["id"] = request_id
            return GatewayResponse(
                status_code=200,
                headers={"content-type": "application/json"},
                body=encode_message(client_response),
            )
        return self._error(
            request_id,
            PROTECTED_EXECUTION_ERROR,
            "protected HTTP execution completed without a relayable provider response",
            data={"execution_id": outcome.execution_id, "retry_safe": False},
        )

    def _fetch_fresh_tool_schema(
        self, tool_name: str, envelope: ModernRequestEnvelope
    ) -> dict[str, Any] | None:
        cursor: str | None = None
        seen_cursors: set[str] = set()
        found: dict[str, Any] | None = None
        found_digest: str | None = None
        tool_count = 0
        for _ in range(self.max_schema_pages):
            request_id = "agschema_" + uuid4().hex
            params: dict[str, Any] = {"_meta": envelope.as_meta()}
            if cursor is not None:
                params["cursor"] = cursor
            request = {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/list",
                "params": params,
            }
            response = self.sender.send(
                encode_message(request), canonical_standard_headers(request)
            )
            if response.status_code < 200 or response.status_code >= 300:
                raise UpstreamTransportError("mcp_http.schema_refresh_http_error")
            parsed = self._parse_upstream_response(response)
            if parsed.get("id") != request_id or "error" in parsed:
                raise UpstreamTransportError("mcp_http.schema_refresh_protocol_error")
            result = parsed.get("result")
            if not isinstance(result, dict):
                raise UpstreamTransportError("mcp_http.schema_refresh_protocol_error")
            tools = result.get("tools")
            if not isinstance(tools, list):
                raise UpstreamTransportError("mcp_http.schema_refresh_protocol_error")
            tool_count += len(tools)
            if tool_count > self.max_schema_tools:
                raise UpstreamTransportError("mcp_http.schema_inventory_limit")
            for item in tools:
                if not isinstance(item, dict):
                    raise UpstreamTransportError("mcp_http.schema_refresh_protocol_error")
                name = item.get("name")
                input_schema = item.get("inputSchema")
                if not isinstance(name, str) or not isinstance(input_schema, dict):
                    raise UpstreamTransportError("mcp_http.schema_refresh_protocol_error")
                if name != tool_name:
                    continue
                schema: dict[str, Any] = {"inputSchema": input_schema}
                # Carry the provider-declared description into the bound schema. The
                # capability classifier is documented to read tool metadata, and it
                # cannot see provider semantics otherwise -- dropping the description
                # here made every such tool classify as `unknown` and therefore
                # denied under a default-deny `unknown_capability`. Binding it also
                # means a provider cannot silently change a tool's declared meaning
                # without changing the schema digest.
                description = item.get("description")
                if isinstance(description, str) and description:
                    schema["description"] = description
                output_schema = item.get("outputSchema")
                if output_schema is not None:
                    if not isinstance(output_schema, dict):
                        raise UpstreamTransportError("mcp_http.schema_refresh_protocol_error")
                    schema["outputSchema"] = output_schema
                current_digest = digest(schema)
                if found_digest is not None and found_digest != current_digest:
                    raise UpstreamTransportError("mcp_http.schema_duplicate_conflict")
                found = schema
                found_digest = current_digest
            next_cursor = result.get("nextCursor")
            if next_cursor is None:
                return found
            if not isinstance(next_cursor, str) or not next_cursor or next_cursor in seen_cursors:
                raise UpstreamTransportError("mcp_http.schema_cursor_invalid")
            seen_cursors.add(next_cursor)
            cursor = next_cursor
        raise UpstreamTransportError("mcp_http.schema_page_limit")

    def _forward(self, message: dict[str, Any]) -> GatewayResponse:
        try:
            response = self.sender.send(
                encode_message(message), canonical_standard_headers(message)
            )
        except UpstreamTransportError:
            return self._error(
                message.get("id"),
                PROTECTED_EXECUTION_ERROR,
                "upstream MCP transport unavailable",
                status_code=502,
            )
        headers: dict[str, str] = {}
        content_type = response.headers.get("content-type")
        if content_type is not None:
            headers["content-type"] = content_type
        cache_control = response.headers.get("cache-control")
        if cache_control is not None:
            headers["cache-control"] = cache_control
        return GatewayResponse(response.status_code, headers, response.body)

    def _parse_upstream_response(self, response: HTTPExchangeResponse) -> dict[str, Any]:
        content_type = response.headers.get("content-type", "").lower()
        if "text/event-stream" in content_type:
            raise UpstreamTransportError("mcp_http.schema_sse_unsupported")
        try:
            value = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise UpstreamTransportError("mcp_http.upstream_json_invalid") from exc
        if not isinstance(value, dict):
            raise UpstreamTransportError("mcp_http.upstream_json_invalid")
        return value

    @staticmethod
    def _error(
        request_id: Any,
        code: int,
        message: str,
        *,
        data: dict[str, Any] | None = None,
        status_code: int = 200,
    ) -> GatewayResponse:
        return GatewayResponse(
            status_code=status_code,
            headers={"content-type": "application/json"},
            body=error_response(request_id, code, message, data),
        )
