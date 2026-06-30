from __future__ import annotations

from collections.abc import Iterable
import json
from typing import Any

from .models import Capability, RiskLevel


SHELL_COMMANDS = {"bash", "sh", "zsh", "fish", "powershell", "python", "python3", "node", "npx"}
CLOUD_COMMANDS = {"aws", "gcloud", "az", "kubectl", "terraform", "pulumi"}
NETWORK_KEYWORDS = {"browser", "fetch", "http", "web", "curl", "wget", "slack", "email"}
DATABASE_KEYWORDS = {"postgres", "mysql", "sqlite", "redis", "mongo", "database", "sql"}
FILESYSTEM_KEYWORDS = {"filesystem", "file", "read_file", "write_file", "path"}
WRITE_KEYWORDS = {"write", "delete", "remove", "move", "rename", "patch", "apply"}
CREDENTIAL_ENV_MARKERS = ("KEY", "TOKEN", "SECRET", "PASSWORD", "CREDENTIAL")


def classify_server(
    command: str | None, args: Iterable[str], env_keys: Iterable[str]
) -> tuple[tuple[Capability, ...], RiskLevel, tuple[str, ...]]:
    caps: set[Capability] = set()
    reasons: list[str] = []
    command_name = (command or "").split("/")[-1].lower()
    lowered_args = " ".join(args).lower()

    if command_name in SHELL_COMMANDS:
        caps.add(Capability.SHELL_EXECUTION)
        reasons.append(f"launches executable runtime '{command_name}'")

    if command_name in CLOUD_COMMANDS or any(keyword in lowered_args for keyword in CLOUD_COMMANDS):
        caps.add(Capability.CLOUD_ACCESS)
        caps.add(Capability.PRODUCTION_MUTATION)
        reasons.append("mentions cloud or infrastructure tooling")

    if any(keyword in lowered_args for keyword in FILESYSTEM_KEYWORDS):
        caps.add(Capability.FILESYSTEM_READ)
        reasons.append("mentions filesystem access")

    if any(keyword in lowered_args for keyword in WRITE_KEYWORDS):
        caps.add(Capability.FILESYSTEM_WRITE)
        reasons.append("mentions write or mutation behavior")

    if any(keyword in lowered_args for keyword in NETWORK_KEYWORDS):
        caps.add(Capability.NETWORK_ACCESS)
        reasons.append("mentions network or browser access")

    if any(keyword in lowered_args for keyword in DATABASE_KEYWORDS):
        caps.add(Capability.DATABASE_ACCESS)
        reasons.append("mentions database access")

    sensitive_env = [
        key for key in env_keys if any(marker in key.upper() for marker in CREDENTIAL_ENV_MARKERS)
    ]
    if sensitive_env:
        caps.add(Capability.CREDENTIAL_ACCESS)
        reasons.append(f"references credential-like env vars: {', '.join(sorted(sensitive_env))}")

    if not caps:
        caps.add(Capability.UNKNOWN)
        reasons.append("capability cannot be inferred from static config")

    return tuple(sorted(caps, key=lambda item: item.value)), _risk_for_capabilities(caps), tuple(reasons)


def classify_tool_name(tool_name: str) -> tuple[Capability, ...]:
    lowered = tool_name.lower()
    caps: set[Capability] = set()
    if any(keyword in lowered for keyword in FILESYSTEM_KEYWORDS):
        caps.add(Capability.FILESYSTEM_READ)
    if any(keyword in lowered for keyword in WRITE_KEYWORDS):
        caps.add(Capability.FILESYSTEM_WRITE)
    if "shell" in lowered or "command" in lowered or "terminal" in lowered:
        caps.add(Capability.SHELL_EXECUTION)
    if any(keyword in lowered for keyword in NETWORK_KEYWORDS):
        caps.add(Capability.NETWORK_ACCESS)
    if any(keyword in lowered for keyword in DATABASE_KEYWORDS):
        caps.add(Capability.DATABASE_ACCESS)
    if "deploy" in lowered or "production" in lowered:
        caps.add(Capability.PRODUCTION_MUTATION)
    if "secret" in lowered or "credential" in lowered:
        caps.add(Capability.CREDENTIAL_ACCESS)
    return tuple(sorted(caps or {Capability.UNKNOWN}, key=lambda item: item.value))


def classify_tool_definition(tool: dict[str, Any]) -> tuple[tuple[Capability, ...], RiskLevel, tuple[str, ...]]:
    caps: set[Capability] = set(classify_tool_name(str(tool.get("name", ""))))
    if Capability.UNKNOWN in caps:
        caps.remove(Capability.UNKNOWN)

    text_parts = [
        str(tool.get("name", "")),
        str(tool.get("description", "")),
        _schema_text(tool.get("inputSchema")),
        _schema_text(tool.get("outputSchema")),
    ]
    lowered = " ".join(text_parts).lower()
    reasons: list[str] = []

    if any(keyword in lowered for keyword in FILESYSTEM_KEYWORDS):
        caps.add(Capability.FILESYSTEM_READ)
        reasons.append("tool metadata mentions filesystem or path access")
    if any(keyword in lowered for keyword in WRITE_KEYWORDS):
        caps.add(Capability.FILESYSTEM_WRITE)
        reasons.append("tool metadata mentions write or mutation behavior")
    if "shell" in lowered or "command" in lowered or "terminal" in lowered:
        caps.add(Capability.SHELL_EXECUTION)
        reasons.append("tool metadata mentions shell or command execution")
    if any(keyword in lowered for keyword in NETWORK_KEYWORDS):
        caps.add(Capability.NETWORK_ACCESS)
        reasons.append("tool metadata mentions network or browser access")
    if any(keyword in lowered for keyword in DATABASE_KEYWORDS):
        caps.add(Capability.DATABASE_ACCESS)
        reasons.append("tool metadata mentions database access")
    if "deploy" in lowered or "production" in lowered:
        caps.add(Capability.PRODUCTION_MUTATION)
        reasons.append("tool metadata mentions deployment or production mutation")
    if "secret" in lowered or "credential" in lowered or "token" in lowered or "api key" in lowered:
        caps.add(Capability.CREDENTIAL_ACCESS)
        reasons.append("tool metadata mentions credentials or secrets")

    if not caps:
        caps.add(Capability.UNKNOWN)
        reasons.append("capability cannot be inferred from tool metadata")

    return tuple(sorted(caps, key=lambda item: item.value)), _risk_for_capabilities(caps), tuple(reasons)


def _schema_text(value: object) -> str:
    if value is None:
        return ""
    try:
        return json.dumps(value, sort_keys=True)
    except TypeError:
        return str(value)


def _risk_for_capabilities(capabilities: set[Capability]) -> RiskLevel:
    if Capability.CREDENTIAL_ACCESS in capabilities or Capability.PRODUCTION_MUTATION in capabilities:
        return RiskLevel.CRITICAL
    if Capability.SHELL_EXECUTION in capabilities or Capability.CLOUD_ACCESS in capabilities:
        return RiskLevel.HIGH
    if Capability.FILESYSTEM_WRITE in capabilities or Capability.DATABASE_ACCESS in capabilities:
        return RiskLevel.HIGH
    if Capability.FILESYSTEM_READ in capabilities or Capability.NETWORK_ACCESS in capabilities:
        return RiskLevel.MEDIUM
    return RiskLevel.LOW
