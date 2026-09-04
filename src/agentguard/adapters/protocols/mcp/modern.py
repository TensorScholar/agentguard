from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Mapping
from urllib.parse import urlsplit, urlunsplit

from agentguard.engine.canonical import digest

MODERN_PROTOCOL_PROFILE = "2026-07-28"
MODERN_HEADER_MISMATCH = -32020
MODERN_MISSING_REQUIRED_CLIENT_CAPABILITY = -32021
MODERN_UNSUPPORTED_PROTOCOL_VERSION = -32022
PROTOCOL_VERSION_META_KEY = "io.modelcontextprotocol/protocolVersion"
CLIENT_INFO_META_KEY = "io.modelcontextprotocol/clientInfo"
CLIENT_CAPABILITIES_META_KEY = "io.modelcontextprotocol/clientCapabilities"

_BASE64_PREFIX = "=?base64?"
_BASE64_SUFFIX = "?="
_HEADER_NAME_RE = re.compile(r"^[!-9;-~]+$")
_MIRRORED_TASK_METHODS = frozenset({"tasks/get", "tasks/update", "tasks/cancel"})


class ModernMCPValidationError(ValueError):
    def __init__(self, reason: str, *, code: int = -32602, http_status: int = 400) -> None:
        super().__init__(reason)
        self.reason = reason
        self.code = code
        self.http_status = http_status


@dataclass(frozen=True)
class ModernRequestEnvelope:
    protocol_version: str
    client_capabilities: dict[str, Any]
    client_info: dict[str, Any] | None
    passthrough_meta: dict[str, Any]

    def as_meta(self) -> dict[str, Any]:
        value = dict(self.passthrough_meta)
        value[PROTOCOL_VERSION_META_KEY] = self.protocol_version
        value[CLIENT_CAPABILITIES_META_KEY] = self.client_capabilities
        if self.client_info is not None:
            value[CLIENT_INFO_META_KEY] = self.client_info
        return value


@dataclass(frozen=True)
class MCPHTTPServerBinding:
    server_id: str
    upstream_url: str
    endpoint_digest: str
    binding_digest: str

    @classmethod
    def for_url(
        cls,
        server_id: str,
        upstream_url: str,
        *,
        allow_insecure_loopback: bool = True,
    ) -> MCPHTTPServerBinding:
        if not server_id or any(character.isspace() for character in server_id):
            raise ValueError("server_id must be a non-empty token without whitespace")
        parsed = urlsplit(upstream_url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError("mcp_http.upstream_scheme_unsupported")
        if parsed.username is not None or parsed.password is not None:
            raise ValueError("mcp_http.upstream_userinfo_denied")
        if parsed.fragment or parsed.query:
            raise ValueError("mcp_http.upstream_query_or_fragment_denied")
        hostname = parsed.hostname
        if not hostname:
            raise ValueError("mcp_http.upstream_host_missing")
        if parsed.scheme == "http":
            if not allow_insecure_loopback or not _is_loopback_host(hostname):
                raise ValueError("mcp_http.insecure_upstream_denied")
        try:
            port = parsed.port
        except ValueError as exc:
            raise ValueError("mcp_http.upstream_port_invalid") from exc
        host = hostname.lower()
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        netloc = host if port is None else f"{host}:{port}"
        path = parsed.path or "/mcp"
        canonical = urlunsplit((parsed.scheme.lower(), netloc, path, "", ""))
        endpoint_digest = digest({"url": canonical})
        return cls(
            server_id=server_id,
            upstream_url=canonical,
            endpoint_digest=endpoint_digest,
            binding_digest=digest(
                {
                    "server_id": server_id,
                    "upstream_url": canonical,
                    "protocol_profile": MODERN_PROTOCOL_PROFILE,
                    "transport": "streamable_http",
                }
            ),
        )


def _is_loopback_host(hostname: str) -> bool:
    if hostname.lower() == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


def _normalize_headers(headers: Mapping[str, str]) -> dict[str, str]:
    return {name.lower(): value for name, value in headers.items()}


def encode_mcp_header_value(value: object) -> str:
    if isinstance(value, bool):
        rendered = "true" if value else "false"
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        rendered = str(value)
    elif isinstance(value, str):
        rendered = value
    else:
        raise ModernMCPValidationError("mcp_http.header_value_type_unsupported")
    unsafe = (
        rendered.startswith(_BASE64_PREFIX)
        and rendered.endswith(_BASE64_SUFFIX)
        or rendered.startswith((" ", "\t"))
        or rendered.endswith((" ", "\t"))
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in rendered)
        or any(ord(character) == 0x7F for character in rendered)
    )
    if not unsafe:
        return rendered
    encoded = base64.b64encode(rendered.encode("utf-8")).decode("ascii")
    return f"{_BASE64_PREFIX}{encoded}{_BASE64_SUFFIX}"


def decode_mcp_header_value(value: str) -> str:
    if not (value.startswith(_BASE64_PREFIX) and value.endswith(_BASE64_SUFFIX)):
        if (
            value.startswith((" ", "\t"))
            or value.endswith((" ", "\t"))
            or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
        ):
            raise ModernMCPValidationError(
                "mcp_http.header_value_malformed", code=MODERN_HEADER_MISMATCH
            )
        return value
    payload = value[len(_BASE64_PREFIX) : -len(_BASE64_SUFFIX)]
    try:
        decoded = base64.b64decode(payload, validate=True)
        return decoded.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as exc:
        raise ModernMCPValidationError(
            "mcp_http.header_base64_malformed", code=MODERN_HEADER_MISMATCH
        ) from exc


def _header_scalar_to_string(value: object) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return str(value)
    if isinstance(value, str):
        return value
    raise ModernMCPValidationError(
        "mcp_http.header_argument_type_unsupported", code=MODERN_HEADER_MISMATCH
    )


def extract_request_envelope(message: dict[str, Any]) -> ModernRequestEnvelope:
    params = message.get("params")
    if not isinstance(params, dict):
        raise ModernMCPValidationError("mcp_modern.params_required")
    meta = params.get("_meta")
    if not isinstance(meta, dict):
        raise ModernMCPValidationError("mcp_modern.meta_required")
    version = meta.get(PROTOCOL_VERSION_META_KEY)
    if version != MODERN_PROTOCOL_PROFILE:
        raise ModernMCPValidationError(
            "mcp_modern.protocol_version_unsupported",
            code=MODERN_UNSUPPORTED_PROTOCOL_VERSION,
        )
    capabilities = meta.get(CLIENT_CAPABILITIES_META_KEY)
    if not isinstance(capabilities, dict):
        raise ModernMCPValidationError("mcp_modern.client_capabilities_required")
    client_info_raw = meta.get(CLIENT_INFO_META_KEY)
    client_info: dict[str, Any] | None = None
    if client_info_raw is not None:
        if not isinstance(client_info_raw, dict):
            raise ModernMCPValidationError("mcp_modern.client_info_malformed")
        name = client_info_raw.get("name")
        version_value = client_info_raw.get("version")
        if not isinstance(name, str) or not name or not isinstance(version_value, str):
            raise ModernMCPValidationError("mcp_modern.client_info_malformed")
        client_info = dict(client_info_raw)
    passthrough = {
        key: value for key, value in meta.items() if not key.startswith("io.modelcontextprotocol/")
    }
    return ModernRequestEnvelope(
        protocol_version=MODERN_PROTOCOL_PROFILE,
        client_capabilities=dict(capabilities),
        client_info=client_info,
        passthrough_meta=passthrough,
    )


def mirrored_name(message: dict[str, Any]) -> str | None:
    method = message.get("method")
    params = message.get("params")
    if not isinstance(method, str) or not isinstance(params, dict):
        return None
    candidate: object | None
    if method in _MIRRORED_TASK_METHODS:
        candidate = params.get("taskId")
    elif method == "resources/read":
        candidate = params.get("uri")
    elif method in {"tools/call", "prompts/get"}:
        candidate = params.get("name")
    else:
        candidate = None
    if candidate is None:
        return None
    if not isinstance(candidate, str):
        raise ModernMCPValidationError(
            "mcp_http.mirrored_name_type_invalid", code=MODERN_HEADER_MISMATCH
        )
    return candidate


def validate_modern_request_headers(
    message: dict[str, Any], headers: Mapping[str, str]
) -> ModernRequestEnvelope:
    if message.get("jsonrpc") != "2.0" or not isinstance(message.get("method"), str):
        raise ModernMCPValidationError("mcp_modern.invalid_jsonrpc_request", code=-32600)
    envelope = extract_request_envelope(message)
    normalized = _normalize_headers(headers)
    version_header = normalized.get("mcp-protocol-version")
    if version_header != MODERN_PROTOCOL_PROFILE:
        raise ModernMCPValidationError(
            "mcp_http.protocol_version_header_mismatch",
            code=MODERN_UNSUPPORTED_PROTOCOL_VERSION,
        )
    method = str(message["method"])
    method_header = normalized.get("mcp-method")
    if method_header != method:
        raise ModernMCPValidationError(
            "mcp_http.method_header_body_mismatch", code=MODERN_HEADER_MISMATCH
        )
    expected_name = mirrored_name(message)
    name_header = normalized.get("mcp-name")
    if expected_name is None:
        if name_header is not None:
            raise ModernMCPValidationError(
                "mcp_http.unexpected_name_header", code=MODERN_HEADER_MISMATCH
            )
    else:
        if name_header is None:
            raise ModernMCPValidationError(
                "mcp_http.name_header_missing", code=MODERN_HEADER_MISMATCH
            )
        if decode_mcp_header_value(name_header) != expected_name:
            raise ModernMCPValidationError(
                "mcp_http.name_header_body_mismatch", code=MODERN_HEADER_MISMATCH
            )
    return envelope


def canonical_standard_headers(message: dict[str, Any]) -> dict[str, str]:
    envelope = extract_request_envelope(message)
    method = message.get("method")
    assert isinstance(method, str)
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "MCP-Protocol-Version": envelope.protocol_version,
        "Mcp-Method": method,
    }
    name = mirrored_name(message)
    if name is not None:
        headers["Mcp-Name"] = encode_mcp_header_value(name)
    return headers


def _header_bindings(tool_schema: dict[str, Any]) -> dict[str, tuple[str, str]]:
    input_schema = tool_schema.get("inputSchema", tool_schema)
    if not isinstance(input_schema, dict):
        raise ModernMCPValidationError("mcp_http.tool_schema_malformed")
    properties = input_schema.get("properties", {})
    if not isinstance(properties, dict):
        raise ModernMCPValidationError("mcp_http.tool_schema_properties_malformed")
    bindings: dict[str, tuple[str, str]] = {}
    seen_headers: set[str] = set()
    for argument_name, property_schema in properties.items():
        if not isinstance(argument_name, str) or not isinstance(property_schema, dict):
            continue
        header_name = property_schema.get("x-mcp-header")
        if header_name is None:
            continue
        if not isinstance(header_name, str) or not _HEADER_NAME_RE.fullmatch(header_name):
            raise ModernMCPValidationError("mcp_http.tool_header_name_invalid")
        if ":" in header_name:
            raise ModernMCPValidationError("mcp_http.tool_header_name_invalid")
        property_type = property_schema.get("type")
        if property_type not in {"string", "integer", "number", "boolean"}:
            raise ModernMCPValidationError("mcp_http.tool_header_type_invalid")
        normalized = header_name.lower()
        if normalized in seen_headers:
            raise ModernMCPValidationError("mcp_http.tool_header_name_duplicate")
        seen_headers.add(normalized)
        bindings[argument_name] = (header_name, str(property_type))
    return bindings


def parameter_headers_for_call(
    message: dict[str, Any], tool_schema: dict[str, Any]
) -> dict[str, str]:
    if message.get("method") != "tools/call":
        return {}
    params = message.get("params")
    if not isinstance(params, dict):
        raise ModernMCPValidationError("mcp_http.tools_call_params_invalid")
    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        raise ModernMCPValidationError("mcp_http.tools_call_arguments_invalid")
    headers: dict[str, str] = {}
    for argument_name, (header_name, _) in _header_bindings(tool_schema).items():
        value = arguments.get(argument_name)
        if value is None:
            continue
        headers[f"Mcp-Param-{header_name}"] = encode_mcp_header_value(value)
    return headers


def validate_parameter_headers(
    message: dict[str, Any], headers: Mapping[str, str], tool_schema: dict[str, Any]
) -> None:
    if message.get("method") != "tools/call":
        return
    params = message.get("params")
    if not isinstance(params, dict):
        raise ModernMCPValidationError("mcp_http.tools_call_params_invalid")
    arguments = params.get("arguments", {})
    if not isinstance(arguments, dict):
        raise ModernMCPValidationError("mcp_http.tools_call_arguments_invalid")
    normalized = _normalize_headers(headers)
    for argument_name, (header_name, _) in _header_bindings(tool_schema).items():
        value = arguments.get(argument_name)
        if value is None:
            continue
        actual = normalized.get(f"mcp-param-{header_name}".lower())
        if actual is None:
            raise ModernMCPValidationError(
                "mcp_http.parameter_header_missing", code=MODERN_HEADER_MISMATCH
            )
        expected = _header_scalar_to_string(value)
        if decode_mcp_header_value(actual) != expected:
            raise ModernMCPValidationError(
                "mcp_http.parameter_header_body_mismatch", code=MODERN_HEADER_MISMATCH
            )


def parse_json_object(body: bytes, *, max_bytes: int) -> dict[str, Any]:
    if len(body) > max_bytes:
        raise ModernMCPValidationError("mcp_http.request_too_large", code=-32600, http_status=413)

    def reject_constant(_: str) -> None:
        raise ValueError("non-finite JSON number")

    try:
        value = json.loads(body.decode("utf-8"), parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise ModernMCPValidationError("mcp_http.parse_error", code=-32700) from exc
    if not isinstance(value, dict):
        raise ModernMCPValidationError("mcp_http.batch_or_non_object_unsupported", code=-32600)
    return value
