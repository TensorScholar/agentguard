from __future__ import annotations

import ipaddress
import posixpath
import unicodedata
from dataclasses import dataclass
from datetime import UTC, date, datetime
from fnmatch import fnmatch
from pathlib import Path, PurePosixPath
from typing import Any
from urllib.parse import unquote, urlparse

import yaml

from .models import Capability, Decision, PolicyDecision, ToolCall
from .risk import classify_tool_name
from .secrets import redact_mapping
from .security.files import read_regular_file


@dataclass(frozen=True)
class ApprovalException:
    exception_id: str
    reason: str
    expires_at: date
    approved_by: str | None = None
    tool: str | None = None
    capabilities: tuple[Capability, ...] = ()


@dataclass(frozen=True)
class Policy:
    default_action: Decision = Decision.DENY
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
    approval_exceptions: tuple[ApprovalException, ...] = ()

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

        excessive_encoding = _first_excessively_encoded_value(call.arguments)
        if excessive_encoding is not None:
            return PolicyDecision(
                decision=Decision.DENY,
                reason="input uses excessive nested URL encoding",
                rule_id="input.excessive_encoding",
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

        approval_capabilities = tuple(
            capability
            for capability in capabilities
            if capability in self.require_approval_capabilities
        )
        if approval_capabilities:
            exception = _matching_approval_exception(
                call=call,
                required_capabilities=approval_capabilities,
                exceptions=self.approval_exceptions,
            )
            if exception:
                approver = f", approved by {exception.approved_by}" if exception.approved_by else ""
                return PolicyDecision(
                    decision=Decision.ALLOW,
                    reason=(
                        f"approval exception '{exception.exception_id}' matched{approver}: "
                        f"{exception.reason}"
                    ),
                    rule_id=f"approval_exception.{_rule_id_fragment(exception.exception_id)}",
                    capabilities=capabilities,
                    redacted_arguments=redact_mapping(call.arguments),
                )
            return PolicyDecision(
                decision=Decision.REQUIRE_APPROVAL,
                reason=(
                    "capability requires approval: "
                    + ", ".join(capability.value for capability in approval_capabilities)
                ),
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
            redacted_arguments=redact_mapping(
                call.arguments
            ),  # never persist raw tokens by default
        )


_POLICY_FIELDS = {
    "default_action",
    "redact_secret_outputs",
    "denied_tools",
    "allowed_tools",
    "blocked_path_patterns",
    "blocked_env_names",
    "blocked_network_hosts",
    "denied_capabilities",
    "require_approval_capabilities",
    "approval_exceptions",
}
_APPROVAL_EXCEPTION_FIELDS = {
    "id",
    "reason",
    "expires_at",
    "approved_by",
    "tool",
    "capabilities",
    "capability",
}


class _StrictPolicyLoader(yaml.SafeLoader):
    def compose_node(self, parent: yaml.Node | None, index: int) -> yaml.Node:
        # types-PyYAML leaves Parser.check_event untyped despite its boolean contract.
        if self.check_event(yaml.AliasEvent):  # type: ignore[no-untyped-call]
            raise ValueError("YAML aliases are not allowed in policy files")
        node = super().compose_node(parent, index)
        if node is None:
            raise ValueError("YAML node composition returned no node")
        return node


def _construct_unique_mapping(
    loader: _StrictPolicyLoader, node: yaml.MappingNode, deep: bool = False
) -> dict[object, object]:
    mapping: dict[object, object] = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        if key in mapping:
            raise ValueError(f"duplicate policy key: {key}")
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictPolicyLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping
)


def load_policy(path: str | None) -> Policy:
    if path is None:
        return Policy()
    raw = _load_strict_yaml(path)
    unknown = set(raw) - _POLICY_FIELDS
    if unknown:
        raise ValueError(f"unknown policy field(s): {', '.join(sorted(unknown))}")

    default_action = Decision(str(raw.get("default_action", "deny")))
    if default_action not in {Decision.ALLOW, Decision.DENY}:
        raise ValueError("default_action must be 'allow' or 'deny'")
    redact_secret_outputs = raw.get("redact_secret_outputs", True)
    if not isinstance(redact_secret_outputs, bool):
        raise TypeError("redact_secret_outputs must be a boolean")

    return Policy(
        default_action=default_action,
        redact_secret_outputs=redact_secret_outputs,
        denied_tools=tuple(_strict_string_list(raw.get("denied_tools", []), "denied_tools")),
        allowed_tools=tuple(_strict_string_list(raw.get("allowed_tools", []), "allowed_tools")),
        blocked_path_patterns=tuple(
            _strict_string_list(raw.get("blocked_path_patterns", []), "blocked_path_patterns")
        )
        or Policy().blocked_path_patterns,
        blocked_env_names=tuple(
            _strict_string_list(raw.get("blocked_env_names", []), "blocked_env_names")
        ),
        blocked_network_hosts=tuple(
            _strict_string_list(raw.get("blocked_network_hosts", []), "blocked_network_hosts")
        )
        or Policy().blocked_network_hosts,
        denied_capabilities=tuple(
            Capability(item)
            for item in _strict_string_list(
                raw.get("denied_capabilities", []), "denied_capabilities"
            )
        ),
        require_approval_capabilities=tuple(
            Capability(item)
            for item in _strict_string_list(
                raw.get("require_approval_capabilities", []),
                "require_approval_capabilities",
            )
        )
        or Policy().require_approval_capabilities,
        approval_exceptions=_approval_exceptions_from_raw(raw.get("approval_exceptions", [])),
    )


def _load_strict_yaml(path: str) -> dict[str, object]:
    raw = read_regular_file(Path(path), maximum_bytes=4 * 1024 * 1024).decode("utf-8")
    loaded = yaml.load(raw, Loader=_StrictPolicyLoader)
    if loaded is None:
        return {}
    if not isinstance(loaded, dict) or not all(isinstance(key, str) for key in loaded):
        raise TypeError("policy root must be a string-keyed mapping")
    return loaded


def _strict_string_list(value: object, field: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise TypeError(f"{field} must be a list")
    if not all(isinstance(item, str) and item.strip() for item in value):
        raise TypeError(f"{field} must contain only non-empty strings")
    return [item.strip() for item in value]


def _approval_exceptions_from_raw(value: object) -> tuple[ApprovalException, ...]:
    if value in (None, "", []):
        return ()
    if not isinstance(value, list):
        raise TypeError("approval_exceptions must be a list")

    exceptions: list[ApprovalException] = []
    seen_ids: set[str] = set()
    for index, item in enumerate(value, start=1):
        if not isinstance(item, dict) or not all(isinstance(key, str) for key in item):
            raise TypeError(f"approval_exceptions[{index}] must be a string-keyed mapping")
        unknown = set(item) - _APPROVAL_EXCEPTION_FIELDS
        if unknown:
            raise ValueError(
                f"approval_exceptions[{index}] has unknown field(s): " + ", ".join(sorted(unknown))
            )
        if "capabilities" in item and "capability" in item:
            raise ValueError(
                f"approval_exceptions[{index}] cannot define both capability and capabilities"
            )

        exception_id = _required_string(item, "id", index)
        if exception_id in seen_ids:
            raise ValueError(f"duplicate approval exception id: {exception_id}")
        seen_ids.add(exception_id)
        reason = _required_string(item, "reason", index)
        expires_at = _parse_date(_required_string(item, "expires_at", index), index)
        approved_by = _optional_string(item, "approved_by")
        tool = _optional_string(item, "tool")
        capability_value = item.get("capabilities", item.get("capability", []))
        if isinstance(capability_value, str):
            capability_names = [capability_value]
        else:
            capability_names = _strict_string_list(
                capability_value, f"approval_exceptions[{index}].capabilities"
            )
        capabilities = tuple(Capability(name) for name in capability_names)
        if not capabilities:
            raise ValueError(f"approval_exceptions[{index}] must include capabilities scope")

        exceptions.append(
            ApprovalException(
                exception_id=exception_id,
                reason=reason,
                expires_at=expires_at,
                approved_by=approved_by,
                tool=tool,
                capabilities=capabilities,
            )
        )
    return tuple(exceptions)


def _required_string(item: dict[str, object], key: str, index: int) -> str:
    value = _optional_string(item, key)
    if not value:
        raise ValueError(f"approval_exceptions[{index}].{key} is required")
    return value


def _optional_string(item: dict[str, object], key: str) -> str | None:
    value = item.get(key)
    if value in (None, ""):
        return None
    if isinstance(value, (str, date)):
        return str(value)
    raise TypeError(f"approval exception field {key} must be a string")


def _parse_date(value: str, index: int) -> date:
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"approval_exceptions[{index}].expires_at must be YYYY-MM-DD") from exc


def _matching_approval_exception(
    call: ToolCall,
    required_capabilities: tuple[Capability, ...],
    exceptions: tuple[ApprovalException, ...],
) -> ApprovalException | None:
    today = datetime.now(UTC).date()
    for exception in exceptions:
        if exception.expires_at < today:
            continue
        if not exception.capabilities:
            continue
        if exception.tool and not fnmatch(call.tool_name.lower(), exception.tool.lower()):
            continue
        if not set(required_capabilities).issubset(set(exception.capabilities)):
            continue
        return exception
    return None


def _rule_id_fragment(value: str) -> str:
    return "".join(
        character if character.isalnum() or character in "-_." else "_" for character in value
    )


def _first_excessively_encoded_value(arguments: dict[str, Any]) -> str | None:
    for value in _walk_values(arguments):
        if not isinstance(value, str) or "%" not in value:
            continue
        try:
            _bounded_unquote(value)
        except ValueError:
            return value
    return None


def _first_blocked_path(arguments: dict[str, Any], patterns: tuple[str, ...]) -> str | None:
    for value in _walk_values(arguments):
        if not isinstance(value, str):
            continue
        try:
            candidate = _normalize_path_candidate(value)
        except ValueError:
            return value
        if candidate is not None and _matches_any_path(candidate, patterns):
            return value
    return None


def _first_blocked_env_name(arguments: dict[str, Any], env_names: tuple[str, ...]) -> str | None:
    wanted = {name.upper() for name in env_names}
    for value in _walk_values(arguments):
        if isinstance(value, str) and value.upper() in wanted:
            return value
    return None


def _first_blocked_host(arguments: dict[str, Any], hosts: tuple[str, ...]) -> str | None:
    blocked = {_normalize_hostname(host) for host in hosts}
    for value in _walk_values(arguments):
        if not isinstance(value, str):
            continue
        try:
            host = _extract_hostname(value)
        except ValueError:
            return value
        if host is None:
            continue
        if host in blocked or _is_link_local_or_metadata(host):
            return host
    return None


def _walk_values(value: object) -> list[object]:
    if isinstance(value, dict):
        output: list[object] = []
        for key, item in value.items():
            output.append(key)
            output.extend(_walk_values(item))
        return output
    if isinstance(value, (list, tuple, set, frozenset)):
        output = []
        for item in value:
            output.extend(_walk_values(item))
        return output
    return [value]


def _bounded_unquote(value: str) -> str:
    current = value
    for _ in range(8):
        decoded = unquote(current)
        if decoded == current:
            return current
        current = decoded
    if unquote(current) != current:
        raise ValueError("excessive nested URL encoding")
    return current


def _normalize_path_candidate(value: str) -> str | None:
    candidate = unicodedata.normalize("NFKC", _bounded_unquote(value.strip()))
    if candidate.lower().startswith("file:"):
        parsed = urlparse(candidate)
        if parsed.scheme.lower() != "file":
            return None
        candidate = parsed.path
    candidate = candidate.replace("\\", "/")
    if not _looks_like_path(candidate):
        return None
    normalized = posixpath.normpath(candidate)
    return normalized.lstrip("/")


def _looks_like_path(value: str) -> bool:
    lower = value.lower()
    return (
        "/" in value
        or "\\" in value
        or value.startswith(".")
        or lower in {".env", ".npmrc"}
        or lower.startswith("file:")
        or PurePosixPath(value).suffix != ""
    )


def _matches_any_path(path: str, patterns: tuple[str, ...]) -> bool:
    normalized = path.strip("/")
    lowered = normalized.casefold()
    for pattern in patterns:
        candidate = _normalize_path_candidate(pattern) or pattern.strip("/")
        candidate = candidate.casefold()
        if (
            fnmatch(lowered, candidate)
            or fnmatch(lowered, f"**/{candidate}")
            or fnmatch(f"/{lowered}", f"*/{candidate}")
        ):
            return True
    return False


def _extract_hostname(value: str) -> str | None:
    candidate = unicodedata.normalize("NFKC", _bounded_unquote(value.strip()))
    if not candidate or any(character.isspace() for character in candidate):
        return None

    literal = (
        candidate[1:-1] if candidate.startswith("[") and candidate.endswith("]") else candidate
    )
    try:
        return _normalize_hostname(str(ipaddress.ip_address(literal)))
    except ValueError:
        pass

    parsed = urlparse(candidate if "://" in candidate else f"//{candidate}")
    try:
        host = parsed.hostname
    except ValueError:
        return None
    return _normalize_hostname(host) if host else None


def _parse_ipv4_number(part: str) -> int | None:
    if not part or part.startswith(("+", "-")):
        return None
    base = 10
    digits = part
    if part.casefold().startswith("0x"):
        base = 16
        digits = part[2:]
    elif len(part) > 1 and part.startswith("0"):
        base = 8
        digits = part[1:]
    if not digits:
        return 0
    allowed = "0123456789abcdef"[:base]
    if any(character.casefold() not in allowed for character in digits):
        return None
    try:
        return int(digits, base)
    except ValueError:
        return None


def _parse_noncanonical_ipv4(candidate: str) -> ipaddress.IPv4Address | None:
    raw_parts = candidate.split(".")
    if raw_parts and raw_parts[-1] == "":
        raw_parts.pop()
    if not 1 <= len(raw_parts) <= 4:
        return None
    numbers = [_parse_ipv4_number(part) for part in raw_parts]
    if any(number is None for number in numbers):
        return None
    values = [int(number) for number in numbers if number is not None]
    if any(number > 255 for number in values[:-1]):
        return None
    last_limit = 256 ** (5 - len(values))
    if values[-1] >= last_limit:
        return None
    numeric = values[-1]
    for index, number in enumerate(values[:-1]):
        numeric += number << (8 * (3 - index))
    try:
        return ipaddress.IPv4Address(numeric)
    except ipaddress.AddressValueError:
        return None


def _normalize_hostname(host: str) -> str:
    candidate = host.strip().strip("[]").rstrip(".").casefold()
    legacy_ipv4 = _parse_noncanonical_ipv4(candidate)
    if legacy_ipv4 is not None:
        return str(legacy_ipv4)
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        try:
            return candidate.encode("idna").decode("ascii")
        except UnicodeError:
            return candidate


def _is_link_local_or_metadata(host: str) -> bool:
    if host in {"metadata.google.internal", "metadata.google.internal."}:
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    effective_address = address
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        effective_address = address.ipv4_mapped
    return effective_address.is_link_local or effective_address == ipaddress.IPv4Address(
        "100.100.100.200"
    )
