from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from hashlib import sha256
from typing import Any
from uuid import uuid4

from agentguard._version import __version__
from agentguard.adapters.protocols.mcp.http_gateway_types import (
    HTTPUpstreamSender,
    UpstreamTransportError,
)
from agentguard.adapters.protocols.mcp.jsonrpc import encode_message
from agentguard.adapters.protocols.mcp.modern import (
    MODERN_PROTOCOL_PROFILE,
    MCPHTTPServerBinding,
    ModernRequestEnvelope,
    canonical_standard_headers,
    parameter_headers_for_call,
)
from agentguard.domain import (
    EvidenceTrustLevel,
    ExternalEffectBinding,
    ProviderIdentity,
    ProviderReconciliationEvidence,
    ReconciliationStatus,
)
from agentguard.engine.canonical import digest


@dataclass(frozen=True)
class MCPHTTPProviderStatusProfile:
    """Trusted contract for one provider-specific, read-only MCP status tool."""

    status_tool: str
    status_tool_schema: dict[str, Any]
    lookup_argument: str = "requestId"
    status_field: str = "status"
    provider_operation_id_field: str | None = "providerOperationId"
    succeeded_values: frozenset[str] = frozenset({"succeeded", "success", "completed"})
    failed_values: frozenset[str] = frozenset({"failed", "failure", "error"})
    pending_values: frozenset[str] = frozenset({"pending", "running", "unknown"})
    source: str = "mcp_http_provider_status"

    def __post_init__(self) -> None:
        tokens = (self.status_tool, self.lookup_argument, self.status_field, self.source)
        if any(not token or len(token) > 300 for token in tokens):
            raise ValueError("provider_status.profile_token_invalid")
        if self.provider_operation_id_field is not None and not self.provider_operation_id_field:
            raise ValueError("provider_status.operation_id_field_invalid")
        if not self.succeeded_values or not self.failed_values:
            raise ValueError("provider_status.terminal_values_required")
        if self.succeeded_values & self.failed_values:
            raise ValueError("provider_status.terminal_values_overlap")
        if (self.succeeded_values | self.failed_values) & self.pending_values:
            raise ValueError("provider_status.pending_values_overlap_terminal")


class MCPHTTPProviderStatusReconciler:
    """Query a provider-declared read-only MCP status tool for a prior protected request.

    The provider profile must guarantee that ``lookup_argument`` indexes the original JSON-RPC
    request id. AgentGuard's protected MCP executor uses the durable execution id as that request id,
    so no raw credential, request body, or provider-generated identifier is required for lookup.
    """

    def __init__(
        self,
        *,
        binding: MCPHTTPServerBinding,
        provider_identity: ProviderIdentity,
        sender: HTTPUpstreamSender,
        profile: MCPHTTPProviderStatusProfile,
    ) -> None:
        self.binding = binding
        self.provider_identity = provider_identity
        self.sender = sender
        self.profile = profile
        self.envelope = ModernRequestEnvelope(
            protocol_version=MODERN_PROTOCOL_PROFILE,
            client_capabilities={},
            client_info={
                "name": "agentguard-provider-reconciler",
                "version": __version__,
            },
            passthrough_meta={},
        )

    @staticmethod
    def _body_digest(body: bytes) -> str:
        return "sha256:" + sha256(body).hexdigest()

    def _unknown(
        self,
        binding: ExternalEffectBinding,
        *,
        observed_at: datetime,
        error_code: str,
        evidence_seed: object,
    ) -> ProviderReconciliationEvidence:
        return ProviderReconciliationEvidence(
            binding_digest=digest(binding),
            source=self.profile.source,
            evidence_digest=digest(evidence_seed),
            trust_level=EvidenceTrustLevel.AGENTGUARD_SIGNED,
            observed_at=observed_at,
            status=ReconciliationStatus.STILL_UNKNOWN,
            error_code=error_code,
        )

    def reconcile(self, binding: ExternalEffectBinding) -> ProviderReconciliationEvidence:
        observed_at = datetime.now(UTC)
        if binding.provider != self.provider_identity:
            raise ValueError("provider_reconciliation.provider_identity_mismatch")
        if self.provider_identity.endpoint_digest != self.binding.endpoint_digest:
            raise ValueError("provider_reconciliation.endpoint_binding_mismatch")
        if binding.operation.operation_kind != "mcp.tools/call":
            raise ValueError("provider_reconciliation.operation_kind_unsupported")

        request_id = "agreconcile_" + uuid4().hex
        message = {
            "jsonrpc": "2.0",
            "id": request_id,
            "method": "tools/call",
            "params": {
                "name": self.profile.status_tool,
                "arguments": {
                    self.profile.lookup_argument: binding.attempt.execution_id,
                },
                "_meta": self.envelope.as_meta(),
            },
        }
        headers = canonical_standard_headers(message)
        headers.update(parameter_headers_for_call(message, self.profile.status_tool_schema))
        try:
            response = self.sender.send(encode_message(message), headers)
        except UpstreamTransportError:
            return self._unknown(
                binding,
                observed_at=observed_at,
                error_code="provider_status.transport_unavailable",
                evidence_seed={
                    "binding_digest": digest(binding),
                    "status_tool": self.profile.status_tool,
                    "error": "transport_unavailable",
                    "observed_at": observed_at,
                },
            )

        response_seed = {
            "binding_digest": digest(binding),
            "status_tool": self.profile.status_tool,
            "http_status": response.status_code,
            "body_digest": self._body_digest(response.body),
        }
        if response.status_code < 200 or response.status_code >= 300:
            return self._unknown(
                binding,
                observed_at=observed_at,
                error_code="provider_status.http_error",
                evidence_seed=response_seed,
            )
        try:
            parsed = json.loads(response.body.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            return self._unknown(
                binding,
                observed_at=observed_at,
                error_code="provider_status.response_invalid",
                evidence_seed=response_seed,
            )
        if not isinstance(parsed, dict) or parsed.get("id") != request_id or "error" in parsed:
            return self._unknown(
                binding,
                observed_at=observed_at,
                error_code="provider_status.protocol_error",
                evidence_seed=response_seed,
            )
        result = parsed.get("result")
        if not isinstance(result, dict):
            return self._unknown(
                binding,
                observed_at=observed_at,
                error_code="provider_status.result_invalid",
                evidence_seed=response_seed,
            )
        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            return self._unknown(
                binding,
                observed_at=observed_at,
                error_code="provider_status.structured_content_required",
                evidence_seed=response_seed,
            )
        provider_status = structured.get(self.profile.status_field)
        if not isinstance(provider_status, str):
            return self._unknown(
                binding,
                observed_at=observed_at,
                error_code="provider_status.state_missing",
                evidence_seed=response_seed,
            )
        normalized = provider_status.strip().lower()
        if normalized in self.profile.succeeded_values:
            status = ReconciliationStatus.CONFIRMED_SUCCEEDED
            error_code = None
        elif normalized in self.profile.failed_values:
            status = ReconciliationStatus.CONFIRMED_FAILED
            error_code = None
        elif normalized in self.profile.pending_values:
            status = ReconciliationStatus.STILL_UNKNOWN
            error_code = None
        else:
            status = ReconciliationStatus.STILL_UNKNOWN
            error_code = "provider_status.state_unrecognized"

        provider_operation_id_digest = None
        field = self.profile.provider_operation_id_field
        if field is not None and field in structured:
            provider_operation_id = structured[field]
            if not isinstance(provider_operation_id, str) or not provider_operation_id:
                return self._unknown(
                    binding,
                    observed_at=observed_at,
                    error_code="provider_status.operation_id_invalid",
                    evidence_seed=response_seed,
                )
            provider_operation_id_digest = digest(provider_operation_id)

        evidence_digest = digest(
            {
                **response_seed,
                "provider_state": normalized,
                "provider_operation_id_digest": provider_operation_id_digest,
            }
        )
        return ProviderReconciliationEvidence(
            binding_digest=digest(binding),
            source=self.profile.source,
            evidence_digest=evidence_digest,
            trust_level=EvidenceTrustLevel.PROVIDER_VERIFIED,
            observed_at=observed_at,
            provider_operation_id_digest=provider_operation_id_digest,
            provider_status=response.status_code,
            error_code=error_code,
            status=status,
        )
