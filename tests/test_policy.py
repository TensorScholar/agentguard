from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest

from agentguard.models import Capability, Decision, ToolCall
from agentguard.policy import ApprovalException, Policy, load_policy


def test_policy_blocks_sensitive_env_file() -> None:
    decision = Policy().evaluate(ToolCall(tool_name="read_file", arguments={"path": ".env"}))

    assert decision.decision == Decision.DENY
    assert decision.rule_id == "path.sensitive"


def test_policy_requires_approval_for_shell_tool() -> None:
    decision = Policy().evaluate(
        ToolCall(tool_name="run_command", arguments={"command": "git status"})
    )

    assert decision.decision == Decision.REQUIRE_APPROVAL
    assert decision.rule_id == "capability.requires_approval"


def test_policy_allows_safe_readme_read() -> None:
    decision = Policy().evaluate(ToolCall(tool_name="read_file", arguments={"path": "README.md"}))

    assert decision.decision == Decision.ALLOW


def test_policy_denies_known_capability() -> None:
    policy = Policy(denied_capabilities=(Capability.CREDENTIAL_ACCESS,))

    decision = policy.evaluate(
        ToolCall(tool_name="get_token", arguments={}),
        known_capabilities=(Capability.CREDENTIAL_ACCESS,),
    )

    assert decision.decision == Decision.DENY
    assert decision.rule_id == "capability.denied"


def test_policy_uses_known_capability_for_approval() -> None:
    decision = Policy().evaluate(
        ToolCall(tool_name="execute", arguments={}),
        known_capabilities=(Capability.SHELL_EXECUTION,),
    )

    assert decision.decision == Decision.REQUIRE_APPROVAL
    assert decision.rule_id == "capability.requires_approval"


def test_approval_exception_allows_matching_required_capability() -> None:
    policy = Policy(
        approval_exceptions=(
            ApprovalException(
                exception_id="local-git-status",
                reason="local repository inspection",
                expires_at=date(2099, 1, 1),
                approved_by="security",
                tool="run_*",
                capabilities=(Capability.SHELL_EXECUTION,),
            ),
        )
    )

    decision = policy.evaluate(
        ToolCall(tool_name="run_command", arguments={"command": "git status"}),
        known_capabilities=(Capability.SHELL_EXECUTION,),
    )

    assert decision.decision == Decision.ALLOW
    assert decision.rule_id == "approval_exception.local-git-status"
    assert "approved by security" in decision.reason


def test_expired_approval_exception_is_ignored() -> None:
    policy = Policy(
        approval_exceptions=(
            ApprovalException(
                exception_id="expired-shell",
                reason="old temporary approval",
                expires_at=date(2000, 1, 1),
                tool="run_command",
                capabilities=(Capability.SHELL_EXECUTION,),
            ),
        )
    )

    decision = policy.evaluate(
        ToolCall(tool_name="run_command", arguments={"command": "git status"}),
        known_capabilities=(Capability.SHELL_EXECUTION,),
    )

    assert decision.decision == Decision.REQUIRE_APPROVAL
    assert decision.rule_id == "capability.requires_approval"


def test_approval_exception_does_not_override_hard_deny() -> None:
    policy = Policy(
        denied_capabilities=(Capability.SHELL_EXECUTION,),
        approval_exceptions=(
            ApprovalException(
                exception_id="shell-exception",
                reason="would otherwise match",
                expires_at=date(2099, 1, 1),
                tool="run_command",
                capabilities=(Capability.SHELL_EXECUTION,),
            ),
        ),
    )

    decision = policy.evaluate(
        ToolCall(tool_name="run_command", arguments={"command": "git status"}),
        known_capabilities=(Capability.SHELL_EXECUTION,),
    )

    assert decision.decision == Decision.DENY
    assert decision.rule_id == "capability.denied"


def test_approval_exception_must_cover_all_required_capabilities() -> None:
    policy = Policy(
        approval_exceptions=(
            ApprovalException(
                exception_id="shell-only",
                reason="covers shell but not production mutation",
                expires_at=date(2099, 1, 1),
                tool="deploy",
                capabilities=(Capability.SHELL_EXECUTION,),
            ),
        )
    )

    decision = policy.evaluate(
        ToolCall(tool_name="deploy", arguments={"target": "production"}),
        known_capabilities=(Capability.SHELL_EXECUTION, Capability.PRODUCTION_MUTATION),
    )

    assert decision.decision == Decision.REQUIRE_APPROVAL
    assert "shell_execution, production_mutation" in decision.reason


def test_load_policy_parses_approval_exceptions(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        """
default_action: allow
require_approval_capabilities:
  - shell_execution
approval_exceptions:
  - id: local-git-status
    reason: local repository inspection
    approved_by: security
    expires_at: 2099-01-01
    tool: run_*
    capabilities:
      - shell_execution
""".lstrip(),
        encoding="utf-8",
    )

    policy = load_policy(str(path))
    decision = policy.evaluate(
        ToolCall(tool_name="run_command", arguments={"command": "git status"}),
        known_capabilities=(Capability.SHELL_EXECUTION,),
    )

    assert decision.decision == Decision.ALLOW
    assert decision.rule_id == "approval_exception.local-git-status"


def test_load_policy_rejects_unscoped_approval_exception(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(
        """
approval_exceptions:
  - id: unsafe
    reason: missing capability scope
    expires_at: 2099-01-01
""".lstrip(),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="must include capabilities scope"):
        load_policy(str(path))
