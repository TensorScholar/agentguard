from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
from typing import Any

from decisionlock.adapters.protocols.mcp.http_gateway import MCPProtectedHTTPGateway
from decisionlock.adapters.protocols.mcp.http_server import HTTPXUpstreamSender
from decisionlock.adapters.protocols.mcp.modern import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    MODERN_PROTOCOL_PROFILE,
    PROTOCOL_VERSION_META_KEY,
    MCPHTTPServerBinding,
    decode_mcp_header_value,
    encode_mcp_header_value,
)
from decisionlock.application import DecisionLockService
from decisionlock.domain import Effect, ExecutionState, Principal, ProvenanceLabel
from decisionlock.domain.policy import (
    ActionMatcher,
    PolicyDefaults,
    PolicyDocument,
    PolicyMetadata,
    PolicyRule,
    ProvenanceMatcher,
)


def _allow_policy() -> PolicyDocument:
    return PolicyDocument(
        metadata=PolicyMetadata(id="phase6ab-real-http", revision=1),
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


def _principal() -> Principal:
    return Principal(
        agent_id="agent",
        workload_id="mcp-http-real",
        tenant_id="tenant",
        identity_verified=False,
    )


def _envelope() -> dict[str, Any]:
    return {
        PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_PROFILE,
        CLIENT_CAPABILITIES_META_KEY: {},
        CLIENT_INFO_META_KEY: {"name": "phase6-real-http", "version": "1.0"},
    }


def _tool_call() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": 91,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "README.md", "region": "eu-west"},
            "_meta": _envelope(),
        },
    }


def _request_headers(message: dict[str, Any]) -> dict[str, str]:
    return {
        "content-type": "application/json",
        "mcp-protocol-version": MODERN_PROTOCOL_PROFILE,
        "mcp-method": "tools/call",
        "mcp-name": encode_mcp_header_value(str(message["params"]["name"])),
        "mcp-param-region": encode_mcp_header_value("eu-west"),
    }


def _response_for(message: dict[str, Any]) -> dict[str, Any]:
    if message["method"] == "tools/list":
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "tools": [
                    {
                        "name": "read_file",
                        "inputSchema": {
                            "type": "object",
                            "properties": {
                                "path": {"type": "string"},
                                "region": {
                                    "type": "string",
                                    "x-mcp-header": "Region",
                                },
                            },
                        },
                    }
                ]
            },
        }
    if message["method"] == "tools/call":
        return {
            "jsonrpc": "2.0",
            "id": message["id"],
            "result": {
                "content": [{"type": "text", "text": "network-ok"}],
                "isError": False,
            },
        }
    return {"jsonrpc": "2.0", "id": message["id"], "result": {}}


def test_protected_call_crosses_real_loopback_http_boundary(signer, verifier, state) -> None:
    calls: list[tuple[dict[str, Any], dict[str, str]]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:  # noqa: N802 - stdlib handler API
            length = int(self.headers.get("content-length", "0"))
            message = json.loads(self.rfile.read(length))
            headers = {key.lower(): value for key, value in self.headers.items()}
            calls.append((message, headers))
            payload = json.dumps(_response_for(message)).encode()
            self.send_response(200)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, format_string: str, *args: object) -> None:
            return None

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    port = int(server.server_address[1])
    binding = MCPHTTPServerBinding.for_url(
        "filesystem-real",
        f"http://127.0.0.1:{port}/mcp",
    )
    sender = HTTPXUpstreamSender(
        binding.upstream_url,
        timeout_seconds=3.0,
        max_response_bytes=100_000,
    )
    subject = MCPProtectedHTTPGateway(
        DecisionLockService(signer, verifier, state),
        _allow_policy(),
        _principal(),
        binding,
        sender,
    )
    message = _tool_call()

    try:
        result = subject.handle(json.dumps(message).encode(), _request_headers(message))
    finally:
        sender.close()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2.0)

    payload = json.loads(result.body)
    assert result.status_code == 200
    assert payload["id"] == 91
    assert payload["result"]["content"][0]["text"] == "network-ok"
    assert [call[0]["method"] for call in calls] == ["tools/list", "tools/call"]

    protected_message, protected_headers = calls[-1]
    assert protected_message["id"].startswith("exec_")
    assert protected_headers["mcp-protocol-version"] == MODERN_PROTOCOL_PROFILE
    assert protected_headers["mcp-method"] == "tools/call"
    assert decode_mcp_header_value(protected_headers["mcp-name"]) == "read_file"
    assert decode_mcp_header_value(protected_headers["mcp-param-region"]) == "eu-west"

    records = state.list_executions()
    assert len(records) == 1
    assert records[0].state == ExecutionState.SUCCEEDED
