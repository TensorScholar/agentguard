from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit


class HTTPTransportSecurityError(ValueError):
    pass


def validate_origin(
    origin: str | None, allowed_origins: frozenset[str], *, browser_reachable: bool = True
) -> None:
    if origin is None:
        if browser_reachable:
            raise HTTPTransportSecurityError("mcp_http.origin_missing")
        return
    if origin not in allowed_origins:
        raise HTTPTransportSecurityError("mcp_http.origin_denied")


def validate_host(host: str, allowed_hosts: frozenset[str]) -> None:
    if any(character in host for character in "/\\?#") or not host:
        raise HTTPTransportSecurityError("mcp_http.host_denied")
    parsed = urlsplit(f"//{host}")
    if parsed.username is not None or parsed.password is not None:
        raise HTTPTransportSecurityError("mcp_http.host_denied")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise HTTPTransportSecurityError("mcp_http.host_denied") from exc
    hostname = (parsed.hostname or "").lower()
    if hostname not in {h.lower() for h in allowed_hosts}:
        raise HTTPTransportSecurityError("mcp_http.host_denied")


def validate_mirrored_headers(
    message: dict[str, Any], method_header: str | None, name_header: str | None
) -> None:
    method = message.get("method")
    if method_header is not None and method_header != method:
        raise HTTPTransportSecurityError("mcp_http.method_header_body_mismatch")
    if method == "tools/call" and name_header is not None:
        params = message.get("params") or {}
        if not isinstance(params, dict) or params.get("name") != name_header:
            raise HTTPTransportSecurityError("mcp_http.name_header_body_mismatch")
