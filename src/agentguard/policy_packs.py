from __future__ import annotations

from dataclasses import dataclass

from .models import Capability, Decision


@dataclass(frozen=True)
class PolicyPack:
    name: str
    description: str
    default_action: Decision
    redact_secret_outputs: bool
    denied_tools: tuple[str, ...]
    allowed_tools: tuple[str, ...]
    blocked_path_patterns: tuple[str, ...]
    blocked_env_names: tuple[str, ...]
    blocked_network_hosts: tuple[str, ...]
    denied_capabilities: tuple[Capability, ...]
    require_approval_capabilities: tuple[Capability, ...]


COMMON_BLOCKED_PATHS = (
    ".env",
    "**/.env",
    ".ssh/**",
    "**/id_rsa",
    ".aws/**",
    ".npmrc",
    ".pypirc",
    ".netrc",
    ".git-credentials",
    "**/.git-credentials",
)

COMMON_BLOCKED_ENV_NAMES = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "DATABASE_URL",
    "GITHUB_TOKEN",
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "NPM_TOKEN",
    "PYPI_TOKEN",
)

COMMON_BLOCKED_NETWORK_HOSTS = (
    "169.254.169.254",
    "metadata.google.internal",
)

POLICY_PACKS: dict[str, PolicyPack] = {
    "coding-agent-local": PolicyPack(
        name="coding-agent-local",
        description=(
            "Local coding-agent guardrail: allow normal repo work, block secrets, gate execution."
        ),
        default_action=Decision.ALLOW,
        redact_secret_outputs=True,
        denied_tools=(),
        allowed_tools=(),
        blocked_path_patterns=COMMON_BLOCKED_PATHS,
        blocked_env_names=COMMON_BLOCKED_ENV_NAMES,
        blocked_network_hosts=COMMON_BLOCKED_NETWORK_HOSTS,
        denied_capabilities=(Capability.CREDENTIAL_ACCESS,),
        require_approval_capabilities=(
            Capability.SHELL_EXECUTION,
            Capability.CLOUD_ACCESS,
            Capability.DATABASE_ACCESS,
            Capability.PRODUCTION_MUTATION,
        ),
    ),
    "ci-agent": PolicyPack(
        name="ci-agent",
        description="CI-agent guardrail: block credentials and production changes, gate mutations.",
        default_action=Decision.ALLOW,
        redact_secret_outputs=True,
        denied_tools=(),
        allowed_tools=(),
        blocked_path_patterns=COMMON_BLOCKED_PATHS,
        blocked_env_names=COMMON_BLOCKED_ENV_NAMES,
        blocked_network_hosts=COMMON_BLOCKED_NETWORK_HOSTS,
        denied_capabilities=(
            Capability.CREDENTIAL_ACCESS,
            Capability.CLOUD_ACCESS,
            Capability.PRODUCTION_MUTATION,
        ),
        require_approval_capabilities=(
            Capability.FILESYSTEM_WRITE,
            Capability.SHELL_EXECUTION,
            Capability.DATABASE_ACCESS,
        ),
    ),
}


def available_policy_packs() -> tuple[str, ...]:
    return tuple(sorted(POLICY_PACKS))


def get_policy_pack(name: str) -> PolicyPack:
    try:
        return POLICY_PACKS[name]
    except KeyError as exc:
        known = ", ".join(available_policy_packs())
        raise ValueError(f"unknown policy pack '{name}'. Available packs: {known}") from exc


def render_policy_pack(name: str) -> str:
    pack = get_policy_pack(name)
    lines = [
        f"# AgentGuard policy pack: {pack.name}",
        f"# {pack.description}",
        f"default_action: {pack.default_action.value}",
        f"redact_secret_outputs: {_yaml_bool(pack.redact_secret_outputs)}",
        "",
    ]
    _append_list(lines, "denied_tools", pack.denied_tools)
    _append_list(lines, "allowed_tools", pack.allowed_tools)
    _append_list(lines, "blocked_path_patterns", pack.blocked_path_patterns)
    _append_list(lines, "blocked_env_names", pack.blocked_env_names)
    _append_list(lines, "blocked_network_hosts", pack.blocked_network_hosts)
    _append_list(lines, "denied_capabilities", _capability_values(pack.denied_capabilities))
    _append_list(
        lines,
        "require_approval_capabilities",
        _capability_values(pack.require_approval_capabilities),
    )
    return "\n".join(lines).rstrip() + "\n"


def _append_list(lines: list[str], key: str, values: tuple[str, ...]) -> None:
    lines.append(f"{key}:")
    for value in values:
        lines.append(f"  - {_quote(value)}")
    lines.append("")


def _quote(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def _yaml_bool(value: bool) -> str:
    return "true" if value else "false"


def _capability_values(values: tuple[Capability, ...]) -> tuple[str, ...]:
    return tuple(item.value for item in values)
