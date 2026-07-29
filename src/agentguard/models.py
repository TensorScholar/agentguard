from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from uuid import uuid4


class RiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Capability(str, Enum):
    FILESYSTEM_READ = "filesystem_read"
    FILESYSTEM_WRITE = "filesystem_write"
    SHELL_EXECUTION = "shell_execution"
    NETWORK_ACCESS = "network_access"
    DATABASE_ACCESS = "database_access"
    CREDENTIAL_ACCESS = "credential_access"
    CLOUD_ACCESS = "cloud_access"
    PRODUCTION_MUTATION = "production_mutation"
    UNKNOWN = "unknown"


class Decision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REQUIRE_APPROVAL = "require_approval"
    REDACT = "redact"


@dataclass(frozen=True)
class ToolCall:
    tool_name: str
    arguments: dict[str, Any] = field(default_factory=dict)
    agent_id: str = "unknown"
    source: str = "local"
    call_id: str = field(default_factory=lambda: uuid4().hex)


@dataclass(frozen=True)
class PolicyDecision:
    decision: Decision
    reason: str
    rule_id: str
    capabilities: tuple[Capability, ...] = ()
    redacted_arguments: dict[str, Any] | None = None

    @property
    def allowed(self) -> bool:
        return self.decision in {Decision.ALLOW, Decision.REDACT}


@dataclass(frozen=True)
class ServerFinding:
    name: str
    command: str | None
    args: tuple[str, ...] = ()
    env_keys: tuple[str, ...] = ()
    capabilities: tuple[Capability, ...] = ()
    risk_level: RiskLevel = RiskLevel.LOW
    reasons: tuple[str, ...] = ()
    config_path: str | None = None


@dataclass(frozen=True)
class ToolInventoryItem:
    source: str
    name: str
    description: str | None = None
    input_schema: dict[str, Any] = field(default_factory=dict)
    output_schema: dict[str, Any] = field(default_factory=dict)
    capabilities: tuple[Capability, ...] = ()
    risk_level: RiskLevel = RiskLevel.LOW
    reasons: tuple[str, ...] = ()
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class ApprovalGrant:
    agent_id: str
    source: str
    tool_name: str
    arguments_hash: str
    approved_by: str
    reason: str
    expires_at: datetime
    max_uses: int = 1
    used_count: int = 0
    grant_id: str = field(default_factory=lambda: uuid4().hex)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass(frozen=True)
class AuditChainVerification:
    ok: bool
    checked_events: int
    head_hash: str
    first_invalid_event_id: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class ScanReport:
    generated_at: datetime
    findings: tuple[ServerFinding, ...]

    @property
    def highest_risk(self) -> RiskLevel:
        order = {
            RiskLevel.LOW: 0,
            RiskLevel.MEDIUM: 1,
            RiskLevel.HIGH: 2,
            RiskLevel.CRITICAL: 3,
        }
        if not self.findings:
            return RiskLevel.LOW
        return max((finding.risk_level for finding in self.findings), key=lambda risk: order[risk])


@dataclass(frozen=True)
class AuditEvent:
    event_id: str
    timestamp: datetime
    agent_id: str
    source: str
    tool_name: str
    call_id: str
    decision: Decision
    reason: str
    rule_id: str
    arguments: dict[str, Any]

    @classmethod
    def from_decision(cls, call: ToolCall, decision: PolicyDecision) -> "AuditEvent":
        return cls(
            event_id=uuid4().hex,
            timestamp=datetime.now(timezone.utc),
            agent_id=call.agent_id,
            source=call.source,
            tool_name=call.tool_name,
            call_id=call.call_id,
            decision=decision.decision,
            reason=decision.reason,
            rule_id=decision.rule_id,
            arguments=decision.redacted_arguments or call.arguments,
        )
