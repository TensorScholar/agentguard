from __future__ import annotations

import json
from typing import Any, Mapping

import httpx
from starlette.testclient import TestClient

from agentguard.adapters.protocols.mcp.http_gateway import (
    HTTPExchangeResponse,
    MCPProtectedHTTPGateway,
)
from agentguard.adapters.protocols.mcp.http_server import create_protected_mcp_http_app
from agentguard.adapters.protocols.mcp.modern import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    MODERN_HEADER_MISMATCH,
    MODERN_PROTOCOL_PROFILE,
    PROTOCOL_VERSION_META_KEY,
    MCPHTTPServerBinding,
    decode_mcp_header_value,
    encode_mcp_header_value,
)
from agentguard.application import AgentGuardService
from agentguard.domain import Effect, ExecutionState, Principal, ProvenanceLabel
from agentguard.domain.policy import (
    ActionMatcher,
    PolicyDefaults,
    PolicyDocument,
    PolicyMetadata,
    PolicyRule,
    ProvenanceMatcher,
)


def allow_policy() -> PolicyDocument:
    return PolicyDocument(
        metadata=PolicyMetadata(id="phase6ab", revision=1),
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


def principal() -> Principal:
    return Principal(
        agent_id="agent",
        workload_id="mcp-http",
        tenant_id="tenant",
        identity_verified=False,
    )


def envelope() -> dict[str, Any]:
    return {
        PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_PROFILE,
        CLIENT_CAPABILITIES_META_KEY: {},
        CLIENT_INFO_META_KEY: {"name": "phase6-test", "version": "1.0"},
    }


def tool_call(*, request_id: int = 7, region: str = "eu-west") -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": "read_file",
            "arguments": {"path": "README.md", "region": region},
            "_meta": envelope(),
        },
    }


def request_headers(message: dict[str, Any], *, region: str = "eu-west") -> dict[str, str]:
    return {
        "content-type": "application/json",
        "mcp-protocol-version": MODERN_PROTOCOL_PROFILE,
        "mcp-method": str(message["method"]),
        "mcp-name": encode_mcp_header_value(str(message["params"]["name"])),
        "mcp-param-region": encode_mcp_header_value(region),
    }


class FakeSender:
    def __init__(self, *, protected_content_type: str = "application/json") -> None:
        self.calls: list[tuple[dict[str, Any], dict[str, str]]] = []
        self.protected_content_type = protected_content_type

    def send(self, body: bytes, headers: Mapping[str, str]) -> HTTPExchangeResponse:
        message = json.loads(body)
        canonical_headers = {key.lower(): value for key, value in headers.items()}
        self.calls.append((message, canonical_headers))
        method = message["method"]
        if method == "tools/list":
            response = {
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
            return HTTPExchangeResponse(
                200,
                {"content-type": "application/json"},
                json.dumps(response).encode(),
            )
        if method == "tools/call":
            if self.protected_content_type == "text/event-stream":
                return HTTPExchangeResponse(
                    200,
                    {"content-type": "text/event-stream"},
                    b"event: message\ndata: {}\n\n",
                )
            response = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": {"content": [{"type": "text", "text": "ok"}]},
            }
            return HTTPExchangeResponse(
                200,
                {"content-type": "application/json"},
                json.dumps(response).encode(),
            )
        response = {"jsonrpc": "2.0", "id": message["id"], "result": {}}
        return HTTPExchangeResponse(
            200,
            {"content-type": "application/json"},
            json.dumps(response).encode(),
        )


def gateway(signer, verifier, state, sender: FakeSender) -> MCPProtectedHTTPGateway:
    binding = MCPHTTPServerBinding.for_url("filesystem", "http://127.0.0.1:9010/mcp")
    return MCPProtectedHTTPGateway(
        AgentGuardService(signer, verifier, state),
        allow_policy(),
        principal(),
        binding,
        sender,
    )


def decode(response_body: bytes) -> dict[str, Any]:
    return json.loads(response_body)


def test_modern_header_codec_round_trips_unsafe_values() -> None:
    encoded = encode_mcp_header_value(" padded 世界 ")
    assert encoded.startswith("=?base64?")
    assert decode_mcp_header_value(encoded) == " padded 世界 "
    sentinel = "=?base64?literal?="
    assert decode_mcp_header_value(encode_mcp_header_value(sentinel)) == sentinel


def test_http_binding_rejects_remote_cleartext() -> None:
    try:
        MCPHTTPServerBinding.for_url("remote", "http://example.com/mcp")
    except ValueError as exc:
        assert str(exc) == "mcp_http.insecure_upstream_denied"
    else:
        raise AssertionError("remote cleartext upstream must be rejected")


def test_protected_modern_call_refreshes_schema_and_canonicalizes_headers(
    signer, verifier, state
) -> None:
    sender = FakeSender()
    subject = gateway(signer, verifier, state, sender)
    message = tool_call()
    result = subject.handle(json.dumps(message).encode(), request_headers(message))
    payload = decode(result.body)
    assert result.status_code == 200
    assert payload["id"] == 7
    assert payload["result"]["content"][0]["text"] == "ok"
    assert [call[0]["method"] for call in sender.calls] == ["tools/list", "tools/call"]
    protected_message, protected_headers = sender.calls[-1]
    assert protected_message["id"].startswith("exec_")
    assert protected_message["id"] != 7
    assert protected_headers["mcp-protocol-version"] == MODERN_PROTOCOL_PROFILE
    assert protected_headers["mcp-method"] == "tools/call"
    assert decode_mcp_header_value(protected_headers["mcp-name"]) == "read_file"
    assert decode_mcp_header_value(protected_headers["mcp-param-region"]) == "eu-west"
    records = state.list_executions()
    assert len(records) == 1
    assert records[0].state == ExecutionState.SUCCEEDED


def test_mcp_param_mismatch_is_blocked_before_external_dispatch(signer, verifier, state) -> None:
    sender = FakeSender()
    subject = gateway(signer, verifier, state, sender)
    message = tool_call(region="eu-west")
    headers = request_headers(message, region="us-east")
    result = subject.handle(json.dumps(message).encode(), headers)
    payload = decode(result.body)
    assert result.status_code == 400
    assert payload["error"]["code"] == MODERN_HEADER_MISMATCH
    assert [call[0]["method"] for call in sender.calls] == ["tools/list"]
    assert state.list_executions() == ()


def test_missing_modern_method_header_is_rejected_without_upstream_io(
    signer, verifier, state
) -> None:
    sender = FakeSender()
    subject = gateway(signer, verifier, state, sender)
    message = tool_call()
    headers = request_headers(message)
    del headers["mcp-method"]
    result = subject.handle(json.dumps(message).encode(), headers)
    payload = decode(result.body)
    assert result.status_code == 400
    assert payload["error"]["code"] == MODERN_HEADER_MISMATCH
    assert sender.calls == []
    assert state.list_executions() == ()


def test_initialize_is_rejected_on_pinned_modern_endpoint(signer, verifier, state) -> None:
    sender = FakeSender()
    subject = gateway(signer, verifier, state, sender)
    message = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"_meta": envelope()},
    }
    headers = {
        "mcp-protocol-version": MODERN_PROTOCOL_PROFILE,
        "mcp-method": "initialize",
    }
    result = subject.handle(json.dumps(message).encode(), headers)
    payload = decode(result.body)
    assert "not valid" in payload["error"]["message"]
    assert sender.calls == []


def test_mrtr_continuation_is_fail_closed_until_ledger_can_bind_pending_state(
    signer, verifier, state
) -> None:
    sender = FakeSender()
    subject = gateway(signer, verifier, state, sender)
    message = tool_call()
    message["params"]["requestState"] = {"opaque": "state"}
    result = subject.handle(json.dumps(message).encode(), request_headers(message))
    payload = decode(result.body)
    assert "MRTR" in payload["error"]["message"]
    assert sender.calls == []
    assert state.list_executions() == ()


def test_protected_sse_response_becomes_durable_unknown_not_success(
    signer, verifier, state
) -> None:
    sender = FakeSender(protected_content_type="text/event-stream")
    subject = gateway(signer, verifier, state, sender)
    message = tool_call()
    result = subject.handle(json.dumps(message).encode(), request_headers(message))
    payload = decode(result.body)
    assert payload["error"]["data"]["retry_safe"] is False
    records = state.list_executions()
    assert len(records) == 1
    assert records[0].state == ExecutionState.UNKNOWN


class FakeStreamForwarder:
    async def open(self, body: bytes, headers: dict[str, str]) -> httpx.Response:
        message = json.loads(body)
        assert message["method"] == "subscriptions/listen"
        assert headers["Mcp-Method"] == "subscriptions/listen"
        return httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=(b'event: message\ndata: {"jsonrpc":"2.0","method":"notifications/test"}\n\n'),
        )

    async def close(self) -> None:
        return None


def test_asgi_boundary_enforces_host_auth_and_relays_subscription_sse(
    signer, verifier, state
) -> None:
    sender = FakeSender()
    subject = gateway(signer, verifier, state, sender)
    app = create_protected_mcp_http_app(
        subject,
        allowed_hosts=frozenset({"testserver"}),
        access_token="test-secret",
        stream_forwarder=FakeStreamForwarder(),  # type: ignore[arg-type]
    )
    message = {
        "jsonrpc": "2.0",
        "id": 44,
        "method": "subscriptions/listen",
        "params": {"_meta": envelope()},
    }
    headers = {
        "content-type": "application/json",
        "mcp-protocol-version": MODERN_PROTOCOL_PROFILE,
        "mcp-method": "subscriptions/listen",
    }
    with TestClient(app) as client:
        denied = client.post("/mcp", json=message, headers=headers)
        assert denied.status_code == 401
        response = client.post(
            "/mcp",
            json=message,
            headers={**headers, "authorization": "Bearer test-secret"},
        )
        assert response.status_code == 200
        assert response.headers["content-type"].startswith("text/event-stream")
        assert "notifications/test" in response.text
        bad_host = client.post(
            "http://evil.example/mcp",
            json=message,
            headers={**headers, "authorization": "Bearer test-secret"},
        )
        assert bad_host.status_code == 403


class FloatSender(FakeSender):
    def __init__(self, result_data: dict[str, Any]) -> None:
        super().__init__()
        self.result_data = result_data

    def send(self, body: bytes, headers: Mapping[str, str]) -> HTTPExchangeResponse:
        message = json.loads(body)
        if message.get("method") == "tools/call":
            response = {
                "jsonrpc": "2.0",
                "id": message["id"],
                "result": self.result_data,
            }
            return HTTPExchangeResponse(
                200,
                {"content-type": "application/json"},
                json.dumps(response).encode(),
            )
        return super().send(body, headers)


def test_http_provider_result_with_finite_floats(signer, verifier, state) -> None:
    float_payload = {"score": 0.5, "price": 12.34, "ratio": 1e-6}
    sender = FloatSender(float_payload)
    subject = gateway(signer, verifier, state, sender)
    call = tool_call(request_id=99)
    response = subject.handle(json.dumps(call).encode(), request_headers(call))
    assert response.status_code == 200
    decoded = json.loads(response.body)
    assert decoded["id"] == 99
    assert "result" in decoded
    assert decoded["result"] == float_payload
    executions = state.list_executions()
    assert len(executions) == 1
    record = executions[0]
    assert record.state == ExecutionState.SUCCEEDED
    assert record.result_digest is not None
    assert record.result_digest.startswith("sha256:")
    assert record.error_code is None


def test_http_provider_result_non_finite_float_rejected(signer, verifier, state) -> None:
    sender = FloatSender({"score": float("nan")})
    subject = gateway(signer, verifier, state, sender)
    call = tool_call(request_id=100)
    response = subject.handle(json.dumps(call).encode(), request_headers(call))
    assert response.status_code == 200
    decoded = json.loads(response.body)
    assert decoded["id"] == 100
    assert "error" in decoded
    assert decoded["error"]["code"] == -32004
    executions = state.list_executions()
    assert len(executions) == 1
    record = executions[0]
    assert record.state == ExecutionState.UNKNOWN
    assert record.error_code == "execution.executor_exception"
