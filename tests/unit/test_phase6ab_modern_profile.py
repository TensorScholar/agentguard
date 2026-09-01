from __future__ import annotations

import json

import pytest

from agentguard.adapters.protocols.mcp.modern import (
    CLIENT_CAPABILITIES_META_KEY,
    MODERN_HEADER_MISMATCH,
    MODERN_PROTOCOL_PROFILE,
    MODERN_UNSUPPORTED_PROTOCOL_VERSION,
    PROTOCOL_VERSION_META_KEY,
    MCPHTTPServerBinding,
    ModernMCPValidationError,
    canonical_standard_headers,
    decode_mcp_header_value,
    encode_mcp_header_value,
    extract_request_envelope,
    mirrored_name,
    parameter_headers_for_call,
    parse_json_object,
    validate_modern_request_headers,
    validate_parameter_headers,
)


def _meta() -> dict[str, object]:
    return {
        PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_PROFILE,
        CLIENT_CAPABILITIES_META_KEY: {"sampling": {}},
        "trace": "kept",
    }


def _request(method: str = "ping", params: dict[str, object] | None = None) -> dict[str, object]:
    return {
        "jsonrpc": "2.0",
        "id": 1,
        "method": method,
        "params": params if params is not None else {"_meta": _meta()},
    }


def test_https_binding_is_canonical_and_bound() -> None:
    binding = MCPHTTPServerBinding.for_url("server-a", "HTTPS://Example.COM:8443/custom")
    assert binding.upstream_url == "https://example.com:8443/custom"
    assert binding.endpoint_digest
    assert binding.binding_digest


@pytest.mark.parametrize(
    "url,reason",
    [
        ("ftp://example.com/mcp", "mcp_http.upstream_scheme_unsupported"),
        ("https://user:secret@example.com/mcp", "mcp_http.upstream_userinfo_denied"),
        ("https://example.com/mcp?q=1", "mcp_http.upstream_query_or_fragment_denied"),
        ("https://example.com/mcp#fragment", "mcp_http.upstream_query_or_fragment_denied"),
        ("http://example.com/mcp", "mcp_http.insecure_upstream_denied"),
    ],
)
def test_binding_rejects_untrusted_endpoint_forms(url: str, reason: str) -> None:
    with pytest.raises(ValueError, match=reason):
        MCPHTTPServerBinding.for_url("server-a", url)


def test_binding_rejects_invalid_server_id_and_port() -> None:
    with pytest.raises(ValueError, match="server_id"):
        MCPHTTPServerBinding.for_url("bad id", "https://example.com/mcp")
    with pytest.raises(ValueError, match="upstream_port_invalid"):
        MCPHTTPServerBinding.for_url("server-a", "https://example.com:99999/mcp")


@pytest.mark.parametrize(
    "value,expected",
    [(True, "true"), (False, "false"), (3, "3"), (1.5, "1.5"), ("plain", "plain")],
)
def test_header_scalar_encoding(value: object, expected: str) -> None:
    assert encode_mcp_header_value(value) == expected


def test_header_codec_rejects_invalid_values() -> None:
    with pytest.raises(ModernMCPValidationError, match="type_unsupported"):
        encode_mcp_header_value({"nested": True})
    with pytest.raises(ModernMCPValidationError) as exc_info:
        decode_mcp_header_value("=?base64?***?=")
    assert exc_info.value.code == MODERN_HEADER_MISMATCH
    with pytest.raises(ModernMCPValidationError, match="header_value_malformed"):
        decode_mcp_header_value(" bad")
    with pytest.raises(ModernMCPValidationError, match="header_value_malformed"):
        decode_mcp_header_value("é")


def test_request_envelope_preserves_only_non_reserved_meta() -> None:
    request = _request()
    envelope = extract_request_envelope(request)
    assert envelope.protocol_version == MODERN_PROTOCOL_PROFILE
    assert envelope.client_capabilities == {"sampling": {}}
    assert envelope.passthrough_meta == {"trace": "kept"}
    assert envelope.as_meta()["trace"] == "kept"


@pytest.mark.parametrize(
    "params,reason,code",
    [
        ({}, "mcp_modern.meta_required", -32602),
        ({"_meta": []}, "mcp_modern.meta_required", -32602),
        (
            {
                "_meta": {
                    PROTOCOL_VERSION_META_KEY: "2025-03-26",
                    CLIENT_CAPABILITIES_META_KEY: {},
                }
            },
            "mcp_modern.protocol_version_unsupported",
            MODERN_UNSUPPORTED_PROTOCOL_VERSION,
        ),
        (
            {"_meta": {PROTOCOL_VERSION_META_KEY: MODERN_PROTOCOL_PROFILE}},
            "mcp_modern.client_capabilities_required",
            -32602,
        ),
    ],
)
def test_envelope_rejects_invalid_shapes(params: dict[str, object], reason: str, code: int) -> None:
    with pytest.raises(ModernMCPValidationError) as exc_info:
        extract_request_envelope(_request(params=params))
    assert exc_info.value.reason == reason
    assert exc_info.value.code == code


def test_client_info_validation() -> None:
    meta = _meta()
    meta["io.modelcontextprotocol/clientInfo"] = {"name": "client", "version": "1"}
    assert extract_request_envelope(_request(params={"_meta": meta})).client_info == {
        "name": "client",
        "version": "1",
    }
    meta["io.modelcontextprotocol/clientInfo"] = {"name": "client"}
    with pytest.raises(ModernMCPValidationError, match="client_info_malformed"):
        extract_request_envelope(_request(params={"_meta": meta}))


def test_mirrored_name_shapes() -> None:
    assert (
        mirrored_name(_request("resources/read", {"uri": "file:///a", "_meta": _meta()}))
        == "file:///a"
    )
    assert mirrored_name(_request("tasks/get", {"taskId": "task-1", "_meta": _meta()})) == "task-1"
    assert mirrored_name(_request("ping")) is None
    with pytest.raises(ModernMCPValidationError, match="mirrored_name_type_invalid"):
        mirrored_name(_request("resources/read", {"uri": 3, "_meta": _meta()}))


def test_standard_headers_are_reconstructed_from_body() -> None:
    request = _request("resources/read", {"uri": "file:///a", "_meta": _meta()})
    headers = canonical_standard_headers(request)
    assert headers["MCP-Protocol-Version"] == MODERN_PROTOCOL_PROFILE
    assert headers["Mcp-Method"] == "resources/read"
    assert decode_mcp_header_value(headers["Mcp-Name"]) == "file:///a"


def test_modern_header_validation_rejects_version_method_name_mismatches() -> None:
    request = _request("resources/read", {"uri": "file:///a", "_meta": _meta()})
    valid = {
        "MCP-Protocol-Version": MODERN_PROTOCOL_PROFILE,
        "Mcp-Method": "resources/read",
        "Mcp-Name": "file:///a",
    }
    assert (
        validate_modern_request_headers(request, valid).protocol_version == MODERN_PROTOCOL_PROFILE
    )

    with pytest.raises(ModernMCPValidationError) as version_error:
        validate_modern_request_headers(request, {**valid, "MCP-Protocol-Version": "2025-03-26"})
    assert version_error.value.code == MODERN_UNSUPPORTED_PROTOCOL_VERSION

    with pytest.raises(ModernMCPValidationError) as method_error:
        validate_modern_request_headers(request, {**valid, "Mcp-Method": "tools/list"})
    assert method_error.value.code == MODERN_HEADER_MISMATCH

    with pytest.raises(ModernMCPValidationError) as name_error:
        validate_modern_request_headers(request, {**valid, "Mcp-Name": "file:///b"})
    assert name_error.value.code == MODERN_HEADER_MISMATCH


def test_unexpected_name_header_is_rejected() -> None:
    request = _request("ping")
    with pytest.raises(ModernMCPValidationError, match="unexpected_name_header"):
        validate_modern_request_headers(
            request,
            {
                "MCP-Protocol-Version": MODERN_PROTOCOL_PROFILE,
                "Mcp-Method": "ping",
                "Mcp-Name": "unexpected",
            },
        )


def _tool_schema() -> dict[str, object]:
    return {
        "inputSchema": {
            "type": "object",
            "properties": {
                "region": {"type": "string", "x-mcp-header": "Region"},
                "attempt": {"type": "integer", "x-mcp-header": "Attempt"},
                "dryRun": {"type": "boolean", "x-mcp-header": "Dry-Run"},
            },
        }
    }


def _tool_call() -> dict[str, object]:
    return _request(
        "tools/call",
        {
            "name": "deploy",
            "arguments": {"region": "eu", "attempt": 2, "dryRun": True},
            "_meta": _meta(),
        },
    )


def test_parameter_headers_are_derived_and_validated() -> None:
    request = _tool_call()
    headers = parameter_headers_for_call(request, _tool_schema())
    assert headers == {
        "Mcp-Param-Region": "eu",
        "Mcp-Param-Attempt": "2",
        "Mcp-Param-Dry-Run": "true",
    }
    validate_parameter_headers(request, headers, _tool_schema())


def test_parameter_header_missing_and_mismatch_are_rejected() -> None:
    request = _tool_call()
    with pytest.raises(ModernMCPValidationError, match="parameter_header_missing"):
        validate_parameter_headers(request, {}, _tool_schema())
    headers = parameter_headers_for_call(request, _tool_schema())
    headers["Mcp-Param-Attempt"] = "3"
    with pytest.raises(ModernMCPValidationError, match="parameter_header_body_mismatch"):
        validate_parameter_headers(request, headers, _tool_schema())


@pytest.mark.parametrize(
    "schema,reason",
    [
        ({"inputSchema": []}, "tool_schema_malformed"),
        ({"inputSchema": {"properties": []}}, "tool_schema_properties_malformed"),
        (
            {"inputSchema": {"properties": {"x": {"type": "object", "x-mcp-header": "X"}}}},
            "tool_header_type_invalid",
        ),
        (
            {"inputSchema": {"properties": {"x": {"type": "string", "x-mcp-header": "Bad:Name"}}}},
            "tool_header_name_invalid",
        ),
        (
            {
                "inputSchema": {
                    "properties": {
                        "a": {"type": "string", "x-mcp-header": "Region"},
                        "b": {"type": "string", "x-mcp-header": "region"},
                    }
                }
            },
            "tool_header_name_duplicate",
        ),
    ],
)
def test_invalid_x_mcp_header_schema_is_rejected(schema: dict[str, object], reason: str) -> None:
    with pytest.raises(ModernMCPValidationError, match=reason):
        parameter_headers_for_call(_tool_call(), schema)


def test_json_parser_is_strict_and_bounded() -> None:
    assert parse_json_object(json.dumps(_request()).encode(), max_bytes=10_000)["method"] == "ping"
    with pytest.raises(ModernMCPValidationError) as too_large:
        parse_json_object(b"{}", max_bytes=1)
    assert too_large.value.http_status == 413
    with pytest.raises(ModernMCPValidationError, match="parse_error"):
        parse_json_object(b"{", max_bytes=10)
    with pytest.raises(ModernMCPValidationError, match="parse_error"):
        parse_json_object(b'{"value": NaN}', max_bytes=100)
    with pytest.raises(ModernMCPValidationError, match="non_object"):
        parse_json_object(b"[]", max_bytes=10)
