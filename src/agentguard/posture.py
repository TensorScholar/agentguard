from __future__ import annotations

import json
from datetime import UTC, datetime
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

from agentguard.security.files import read_regular_file


class EnforcementStatus(str, Enum):
    PROTECTED = "protected"
    DIRECT = "direct"
    AMBIGUOUS = "ambiguous"
    INVALID = "invalid"


class EnforcementRoute(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    config_path: str
    server_name: str
    status: EnforcementStatus
    command: str | None = None
    args: tuple[str, ...] = ()
    url: str | None = None
    downstream_fingerprint: str | None = None
    reason_codes: tuple[str, ...] = ()


class EnforcementPostureReport(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    schema_version: str = "1"
    generated_at: datetime
    routes: tuple[EnforcementRoute, ...]
    protected_count: int = Field(ge=0)
    direct_count: int = Field(ge=0)
    ambiguous_count: int = Field(ge=0)
    invalid_count: int = Field(ge=0)
    duplicate_bypass_fingerprints: tuple[str, ...] = ()

    @property
    def has_bypass(self) -> bool:
        return self.direct_count > 0 or bool(self.duplicate_bypass_fingerprints)


class PostureScanError(ValueError):
    pass


def scan_enforcement_posture(paths: list[Path]) -> EnforcementPostureReport:
    routes: list[EnforcementRoute] = []
    for path in paths:
        routes.extend(_scan_config(path))

    by_fingerprint: dict[str, set[EnforcementStatus]] = {}
    for route in routes:
        if route.downstream_fingerprint:
            by_fingerprint.setdefault(route.downstream_fingerprint, set()).add(route.status)
    duplicate_bypasses = tuple(
        sorted(
            fingerprint
            for fingerprint, statuses in by_fingerprint.items()
            if EnforcementStatus.PROTECTED in statuses and EnforcementStatus.DIRECT in statuses
        )
    )
    if duplicate_bypasses:
        routes = [
            route.model_copy(
                update={
                    "reason_codes": (*route.reason_codes, "mcp.parallel_direct_bypass")
                }
            )
            if route.status == EnforcementStatus.DIRECT
            and route.downstream_fingerprint in duplicate_bypasses
            else route
            for route in routes
        ]

    counts = {status: 0 for status in EnforcementStatus}
    for route in routes:
        counts[route.status] += 1
    return EnforcementPostureReport(
        generated_at=datetime.now(UTC),
        routes=tuple(routes),
        protected_count=counts[EnforcementStatus.PROTECTED],
        direct_count=counts[EnforcementStatus.DIRECT],
        ambiguous_count=counts[EnforcementStatus.AMBIGUOUS],
        invalid_count=counts[EnforcementStatus.INVALID],
        duplicate_bypass_fingerprints=duplicate_bypasses,
    )


def _scan_config(path: Path) -> list[EnforcementRoute]:
    try:
        payload = json.loads(read_regular_file(path, maximum_bytes=8 * 1024 * 1024))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError) as exc:
        raise PostureScanError(f"invalid MCP configuration: {path}") from exc
    if not isinstance(payload, dict):
        raise PostureScanError(f"MCP configuration root must be an object: {path}")
    servers = payload.get("mcpServers", payload)
    if not isinstance(servers, dict):
        raise PostureScanError(f"mcpServers must be an object: {path}")

    routes: list[EnforcementRoute] = []
    for name, raw in sorted(servers.items(), key=lambda item: str(item[0])):
        if not isinstance(raw, dict):
            routes.append(
                EnforcementRoute(
                    config_path=str(path),
                    server_name=str(name),
                    status=EnforcementStatus.INVALID,
                    reason_codes=("mcp.route_not_object",),
                )
            )
            continue
        routes.append(_classify_route(path, str(name), raw))
    return routes


def _classify_route(path: Path, name: str, raw: dict[str, Any]) -> EnforcementRoute:
    command = raw.get("command")
    args = raw.get("args", [])
    url = raw.get("url", raw.get("endpoint"))
    if command is not None and not isinstance(command, str):
        return EnforcementRoute(
            config_path=str(path),
            server_name=name,
            status=EnforcementStatus.INVALID,
            reason_codes=("mcp.command_invalid",),
        )
    if not isinstance(args, list) or not all(isinstance(item, str) for item in args):
        return EnforcementRoute(
            config_path=str(path),
            server_name=name,
            status=EnforcementStatus.INVALID,
            command=command,
            reason_codes=("mcp.args_invalid",),
        )
    if url is not None and not isinstance(url, str):
        return EnforcementRoute(
            config_path=str(path),
            server_name=name,
            status=EnforcementStatus.INVALID,
            command=command,
            args=tuple(args),
            reason_codes=("mcp.url_invalid",),
        )

    tokens = ([command] if command else []) + list(args)
    proxy_index = _proxy_token_index(tokens)
    if proxy_index is not None:
        try:
            separator = tokens.index("--", proxy_index + 1)
        except ValueError:
            return EnforcementRoute(
                config_path=str(path),
                server_name=name,
                status=EnforcementStatus.AMBIGUOUS,
                command=command,
                args=tuple(args),
                url=url,
                reason_codes=("mcp.proxy_target_unverifiable",),
            )
        downstream = tokens[separator + 1 :]
        if not downstream:
            return EnforcementRoute(
                config_path=str(path),
                server_name=name,
                status=EnforcementStatus.INVALID,
                command=command,
                args=tuple(args),
                url=url,
                reason_codes=("mcp.proxy_target_missing",),
            )
        return EnforcementRoute(
            config_path=str(path),
            server_name=name,
            status=EnforcementStatus.PROTECTED,
            command=command,
            args=tuple(args),
            url=url,
            downstream_fingerprint=_fingerprint(downstream),
            reason_codes=("mcp.agentguard_proxy_enforced",),
        )

    if command:
        return EnforcementRoute(
            config_path=str(path),
            server_name=name,
            status=EnforcementStatus.DIRECT,
            command=command,
            args=tuple(args),
            url=url,
            downstream_fingerprint=_fingerprint([command, *args]),
            reason_codes=("mcp.direct_connection_bypasses_agentguard",),
        )
    if url:
        return EnforcementRoute(
            config_path=str(path),
            server_name=name,
            status=EnforcementStatus.DIRECT,
            url=url,
            downstream_fingerprint=_fingerprint(["url", url]),
            reason_codes=("mcp.remote_connection_bypasses_agentguard",),
        )
    return EnforcementRoute(
        config_path=str(path),
        server_name=name,
        status=EnforcementStatus.INVALID,
        reason_codes=("mcp.route_missing_transport",),
    )


def _proxy_token_index(tokens: list[str]) -> int | None:
    if not tokens:
        return None
    normalized = [Path(token).name.casefold() for token in tokens]
    command = normalized[0]

    if command in {"agentguard", "agentguard.exe"}:
        return 1 if len(normalized) > 1 and normalized[1] == "mcp-proxy" else None

    python_commands = {"python", "python.exe", "python3", "python3.exe", "py", "py.exe"}
    if command in python_commands:
        if len(normalized) > 3 and normalized[1] == "-m":
            if normalized[2] in {"agentguard", "agentguard.cli"}:
                return 3 if normalized[3] == "mcp-proxy" else None
        return None

    if command in {"uvx", "uvx.exe"}:
        return 2 if len(normalized) > 2 and normalized[1:3] == ["agentguard", "mcp-proxy"] else None

    return None


def _fingerprint(tokens: list[str]) -> str:
    encoded = json.dumps(tokens, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return sha256(encoded).hexdigest()
