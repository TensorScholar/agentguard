from __future__ import annotations
import json,pytest
from agentguard.adapters.protocols.mcp import parse_message,MCPProtocolError,validate_origin,validate_host,validate_mirrored_headers,HTTPTransportSecurityError

def test_parse_valid_jsonrpc(): assert parse_message(b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}')['id']==1
@pytest.mark.parametrize('raw,code',[(b'bad',-32700),(b'[]',-32600),(b'{"id":1}',-32600)])
def test_invalid_jsonrpc(raw,code):
    with pytest.raises(MCPProtocolError) as e: parse_message(raw)
    assert e.value.code==code

def test_message_limit():
    with pytest.raises(MCPProtocolError,match="large"): parse_message(b'x'*11,max_bytes=10)

def test_origin_allowlist(): validate_origin("https://app.example",frozenset({"https://app.example"}))

def test_origin_denied():
    with pytest.raises(HTTPTransportSecurityError,match="origin_denied"): validate_origin("https://evil.example",frozenset({"https://app.example"}))

def test_missing_origin_denied():
    with pytest.raises(HTTPTransportSecurityError,match="origin_missing"): validate_origin(None,frozenset())

def test_host_denied():
    with pytest.raises(HTTPTransportSecurityError,match="host_denied"): validate_host("evil.example",frozenset({"127.0.0.1"}))

def test_method_header_body_mismatch():
    with pytest.raises(HTTPTransportSecurityError,match="method_header_body_mismatch"): validate_mirrored_headers({"method":"tools/call"},"tools/list",None)

def test_name_header_body_mismatch():
    with pytest.raises(HTTPTransportSecurityError,match="name_header_body_mismatch"): validate_mirrored_headers({"method":"tools/call","params":{"name":"read"}},"tools/call","write")

def test_missing_origin_allowed_for_non_browser():
    validate_origin(None, frozenset(), browser_reachable=False)


def test_host_allowed():
    validate_host("127.0.0.1:8000", frozenset({"127.0.0.1"}))


def test_matching_headers_allowed():
    validate_mirrored_headers(
        {"method": "tools/call", "params": {"name": "read"}}, "tools/call", "read"
    )
