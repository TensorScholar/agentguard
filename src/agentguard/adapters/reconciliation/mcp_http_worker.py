from __future__ import annotations

from agentguard.adapters.protocols.mcp.http_gateway_types import HTTPUpstreamSender
from agentguard.adapters.protocols.mcp.modern import MCPHTTPServerBinding
from agentguard.domain import ExternalEffectBinding, ProviderReconciliationEvidence

from .mcp_http import MCPHTTPProviderStatusProfile, MCPHTTPProviderStatusReconciler


class MCPHTTPBoundStatusReconciler:
    """Reconcile any durable binding on one configured MCP HTTP endpoint."""

    def __init__(
        self,
        *,
        binding: MCPHTTPServerBinding,
        sender: HTTPUpstreamSender,
        profile: MCPHTTPProviderStatusProfile,
    ) -> None:
        self.binding = binding
        self.sender = sender
        self.profile = profile

    def reconcile(self, effect: ExternalEffectBinding) -> ProviderReconciliationEvidence:
        return MCPHTTPProviderStatusReconciler(
            binding=self.binding,
            provider_identity=effect.provider,
            sender=self.sender,
            profile=self.profile,
        ).reconcile(effect)
