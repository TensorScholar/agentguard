from __future__ import annotations

from agentguard.models import Capability, Decision, ToolCall
from agentguard.policy import Policy


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
