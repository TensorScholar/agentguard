from __future__ import annotations

import json
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any

from decisionlock.adapters.protocols.mcp.http_server import HTTPXUpstreamSender
from decisionlock.adapters.protocols.mcp.modern import MCPHTTPServerBinding
from decisionlock.adapters.reconciliation import (
    MCPHTTPProviderStatusProfile,
    MCPHTTPProviderStatusReconciler,
)
from decisionlock.domain import (
    EvidenceTrustLevel,
    ExecutionAttemptIdentity,
    ExternalEffectBinding,
    ExternalOperationIdentity,
    IdempotencyBinding,
    ProviderIdentity,
    ReconciliationStatus,
)
from decisionlock.engine.provider_contracts import external_effect_binding_digest


def test_provider_status_reconciliation_crosses_real_loopback_http_boundary() -> None:
    calls: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            length = int(self.headers.get("content-length", "0"))
            message = json.loads(self.rfile.read(length))
            calls.append(message)
            assert message["method"] == "tools/call"
            assert message["params"]["name"] == "operation_status"
            assert message["params"]["arguments"]["requestId"] == "exec_network_1"
            response = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {
                    "structuredContent": {
                        "status": "completed",
                        "providerOperationId": "provider-network-44",
                    }
                },
            }
            payload = json.dumps(response).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format_string: str, *args: object) -> None:
            del format_string, args

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    server_binding = MCPHTTPServerBinding.for_url(
        "provider-network",
        f"http://127.0.0.1:{port}/mcp",
    )
    provider = ProviderIdentity(
        provider_id="provider-network",
        endpoint_digest=server_binding.endpoint_digest,
    )
    effect = ExternalEffectBinding(
        decision_id="decision_network_1",
        intent_digest="sha256:" + "1" * 64,
        action_digest="sha256:" + "2" * 64,
        resource_digest="sha256:" + "3" * 64,
        arguments_digest="sha256:" + "4" * 64,
        provider=provider,
        operation=ExternalOperationIdentity(
            operation_id="operation_network_1",
            operation_kind="mcp.tools/call",
            operation_name="read_file",
        ),
        attempt=ExecutionAttemptIdentity(
            execution_id="exec_network_1",
            attempt_id="attempt_network_1",
            attempt_number=1,
            started_at=datetime(2026, 9, 2, 12, 0, tzinfo=UTC),
        ),
        idempotency=IdempotencyBinding(),
    )
    sender = HTTPXUpstreamSender(
        server_binding.upstream_url,
        timeout_seconds=3.0,
        max_response_bytes=100_000,
    )
    reconciler = MCPHTTPProviderStatusReconciler(
        binding=server_binding,
        provider_identity=provider,
        sender=sender,
        profile=MCPHTTPProviderStatusProfile(
            status_tool="operation_status",
            status_tool_schema={
                "inputSchema": {
                    "type": "object",
                    "properties": {"requestId": {"type": "string"}},
                    "required": ["requestId"],
                }
            },
        ),
    )

    try:
        evidence = reconciler.reconcile(effect)
    finally:
        sender.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    assert len(calls) == 1
    assert evidence.binding_digest == external_effect_binding_digest(effect)
    assert evidence.status == ReconciliationStatus.CONFIRMED_SUCCEEDED
    assert evidence.trust_level == EvidenceTrustLevel.PROVIDER_VERIFIED
    assert evidence.provider_status == 200
    assert evidence.provider_operation_id_digest is not None
