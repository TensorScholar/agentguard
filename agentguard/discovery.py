from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import ScanReport, ServerFinding
from .risk import classify_server


DEFAULT_CONFIG_CANDIDATES = (
    Path.home() / "Library/Application Support/Claude/claude_desktop_config.json",
    Path.home() / ".cursor/mcp.json",
    Path.home() / ".config/mcp/config.json",
)


class ConfigDiscoveryError(ValueError):
    pass


def discover_config_paths(explicit_paths: list[Path] | None = None) -> list[Path]:
    if explicit_paths:
        return [path for path in explicit_paths if path.exists()]
    return [path for path in DEFAULT_CONFIG_CANDIDATES if path.exists()]


def scan_configs(paths: list[Path]) -> ScanReport:
    findings: list[ServerFinding] = []
    for path in paths:
        findings.extend(_scan_single_config(path))
    return ScanReport(generated_at=datetime.now(timezone.utc), findings=tuple(findings))


def _scan_single_config(path: Path) -> list[ServerFinding]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigDiscoveryError(f"Invalid JSON in {path}: {exc}") from exc

    servers = _extract_servers(raw)
    findings: list[ServerFinding] = []
    for name, config in servers.items():
        command = _optional_string(config.get("command"))
        args = tuple(str(item) for item in config.get("args", []) if item is not None)
        env = config.get("env", {})
        env_keys = tuple(str(key) for key in env.keys()) if isinstance(env, dict) else ()
        capabilities, risk, reasons = classify_server(command, args, env_keys)
        findings.append(
            ServerFinding(
                name=name,
                command=command,
                args=args,
                env_keys=env_keys,
                capabilities=capabilities,
                risk_level=risk,
                reasons=reasons,
                config_path=str(path),
            )
        )
    return findings


def _extract_servers(raw: Any) -> dict[str, dict[str, Any]]:
    if not isinstance(raw, dict):
        raise ConfigDiscoveryError("MCP config must be a JSON object")

    candidate = raw.get("mcpServers", raw)
    if not isinstance(candidate, dict):
        raise ConfigDiscoveryError("MCP config must contain an object named 'mcpServers'")

    servers: dict[str, dict[str, Any]] = {}
    for name, value in candidate.items():
        if isinstance(value, dict):
            servers[str(name)] = value
    return servers


def _optional_string(value: object) -> str | None:
    if value is None:
        return None
    return str(value)
