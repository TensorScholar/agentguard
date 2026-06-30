from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatch
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import urlparse

from .models import Capability, Decision, PolicyDecision, ToolCall
from .risk import classify_tool_name
from .secrets import redact_value


@dataclass(frozen=True)
class Policy:
    default_action: Decision = Decision.ALLOW
    redact_secret_outputs: bool = True
    denied_tools: tuple[str, ...] = ()
    allowed_tools: tuple[str, ...] = ()
    blocked_path_patterns: tuple[str, ...] = (
        ".env",
        "**/.env",
        ".ssh/**",
        "**/id_rsa",
        ".aws/**",
        ".npmrc",
    )
    blocked_env_names: tuple[str, ...] = ()
    blocked_network_hosts: tuple[str, ...] = ("169.254.169.254", "metadata.google.internal")
    denied_capabilities: tuple[Capability, ...] = ()
    require_approval_capabilities: tuple[Capability, ...] = (
        Capability.SHELL_EXECUTION,
        Capability.PRODUCTION_MUTATION,
    )

    def evaluate(
        self, call: ToolCall, known_capabilities: tuple[Capability, ...] | None = None
    ) -> PolicyDecision:
        tool_name = call.tool_name.lower()
        capabilities = known_capabilities or classify_tool_name(call.tool_name)

        if self.allowed_tools and tool_name not in {item.lower() for item in self.allowed_tools}:
            return PolicyDecision(
                decision=Decision.DENY,
                reason="tool is not in allowed_tools",
                rule_id="tool.allowlist",
                capabilities=capabilities,
            )

        if tool_name in {item.lower() for item in self.denied_tools}:
            return PolicyDecision(
                decision=Decision.DENY,
                reason="tool is explicitly denied",
                rule_id="tool.denylist",
                capabilities=capabilities,
            )

        sensitive_path = _first_blocked_path(call.arguments, self.blocked_path_patterns)
        if sensitive_path:
            return PolicyDecision(
                decision=Decision.DENY,
                reason=f"blocked sensitive path: {sensitive_path}",
                rule_id="path.sensitive",
                capabilities=capabilities,
            )

        env_name = _first_blocked_env_name(call.arguments, self.blocked_env_names)
        if env_name:
            return PolicyDecision(
                decision=Decision.DENY,
                reason=f"blocked sensitive environment variable: {env_name}",
                rule_id="env.sensitive",
                capabilities=capabilities,
            )

        blocked_host = _first_blocked_host(call.arguments, self.blocked_network_hosts)
        if blocked_host:
            return PolicyDecision(
                decision=Decision.DENY,
                reason=f"blocked network destination: {blocked_host}",
                rule_id="network.blocked_host",
                capabilities=capabilities,
            )

        denied_capability = next(
            (capability for capability in capabilities if capability in self.denied_capabilities),
            None,
        )
        if denied_capability:
            return PolicyDecision(
                decision=Decision.DENY,
                reason=f"capability is denied: {denied_capability.value}",
                rule_id="capability.denied",
                capabilities=capabilities,
            )

        approval_capability = next(
            (capability for capability in capabilities if capability in self.require_approval_capabilities),
            None,
        )
        if approval_capability:
            return PolicyDecision(
                decision=Decision.REQUIRE_APPROVAL,
                reason=f"capability requires approval: {approval_capability.value}",
                rule_id="capability.requires_approval",
                capabilities=capabilities,
            )

        if self.default_action == Decision.DENY:
            return PolicyDecision(
                decision=Decision.DENY,
                reason="default action is deny",
                rule_id="default.deny",
                capabilities=capabilities,
            )

        return PolicyDecision(
            decision=Decision.ALLOW,
            reason="no policy rule denied the call",
            rule_id="default.allow",
            capabilities=capabilities,
            redacted_arguments=redact_value(call.arguments),  # never persist raw tokens by default
        )


def load_policy(path: str | None) -> Policy:
    if path is None:
        return Policy()
    raw = _load_simple_yaml(path)
    return Policy(
        default_action=Decision(str(raw.get("default_action", "allow"))),
        redact_secret_outputs=bool(raw.get("redact_secret_outputs", True)),
        denied_tools=tuple(_as_string_list(raw.get("denied_tools", []))),
        allowed_tools=tuple(_as_string_list(raw.get("allowed_tools", []))),
        blocked_path_patterns=tuple(_as_string_list(raw.get("blocked_path_patterns", [])))
        or Policy().blocked_path_patterns,
        blocked_env_names=tuple(_as_string_list(raw.get("blocked_env_names", []))),
        blocked_network_hosts=tuple(_as_string_list(raw.get("blocked_network_hosts", [])))
        or Policy().blocked_network_hosts,
        denied_capabilities=tuple(
            Capability(item) for item in _as_string_list(raw.get("denied_capabilities", []))
        ),
        require_approval_capabilities=tuple(
            Capability(item) for item in _as_string_list(raw.get("require_approval_capabilities", []))
        )
        or Policy().require_approval_capabilities,
    )


def _load_simple_yaml(path: str) -> dict[str, object]:
    result: dict[str, object] = {}
    current_key: str | None = None
    with open(path, encoding="utf-8") as handle:
        for raw_line in handle:
            line = raw_line.split("#", 1)[0].rstrip()
            if not line.strip():
                continue
            if line.startswith("  - ") and current_key:
                result.setdefault(current_key, [])
                value = line[4:].strip().strip("\"'")
                assert isinstance(result[current_key], list)
                result[current_key].append(value)
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                current_key = key.strip()
                value = value.strip()
                if value == "":
                    result[current_key] = []
                else:
                    result[current_key] = _coerce_scalar(value)
    return result


def _coerce_scalar(value: str) -> object:
    normalized = value.strip().strip("\"'")
    if normalized.lower() == "true":
        return True
    if normalized.lower() == "false":
        return False
    return normalized


def _as_string_list(value: object) -> list[str]:
    if isinstance(value, list):
        return [str(item) for item in value]
    if isinstance(value, tuple):
        return [str(item) for item in value]
    if value:
        return [str(value)]
    return []


def _first_blocked_path(arguments: dict[str, Any], patterns: tuple[str, ...]) -> str | None:
    for value in _walk_values(arguments):
        if not isinstance(value, str):
            continue
        normalized = value.replace("\\", "/")
        if _looks_like_path(normalized) and _matches_any_path(normalized, patterns):
            return value
    return None


def _first_blocked_env_name(arguments: dict[str, Any], env_names: tuple[str, ...]) -> str | None:
    wanted = {name.upper() for name in env_names}
    for value in _walk_values(arguments):
        if isinstance(value, str) and value.upper() in wanted:
            return value
    return None


def _first_blocked_host(arguments: dict[str, Any], hosts: tuple[str, ...]) -> str | None:
    blocked = {host.lower() for host in hosts}
    for value in _walk_values(arguments):
        if not isinstance(value, str):
            continue
        parsed = urlparse(value)
        host = (parsed.hostname or "").lower()
        if host in blocked:
            return host
    return None


def _walk_values(value: object) -> list[object]:
    if isinstance(value, dict):
        output: list[object] = []
        for key, item in value.items():
            output.append(key)
            output.extend(_walk_values(item))
        return output
    if isinstance(value, list):
        output = []
        for item in value:
            output.extend(_walk_values(item))
        return output
    return [value]


def _looks_like_path(value: str) -> bool:
    return (
        "/" in value
        or value.startswith(".")
        or value in {".env", ".npmrc"}
        or PurePosixPath(value).suffix != ""
    )


def _matches_any_path(path: str, patterns: tuple[str, ...]) -> bool:
    normalized = path.strip("/")
    for pattern in patterns:
        candidate = pattern.strip("/")
        if fnmatch(normalized, candidate) or fnmatch(path, pattern):
            return True
    return False
