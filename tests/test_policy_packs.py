from __future__ import annotations

from pathlib import Path

from agentguard.models import Capability, Decision, ToolCall
from agentguard.policy import load_policy
from agentguard.policy_packs import available_policy_packs, get_policy_pack, render_policy_pack


def test_policy_pack_catalog_contains_supported_packs() -> None:
    assert available_policy_packs() == ("ci-agent", "coding-agent-local")


def test_coding_agent_local_pack_blocks_credentials_and_gates_shell(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(render_policy_pack("coding-agent-local"), encoding="utf-8")
    policy = load_policy(str(path))

    credential_decision = policy.evaluate(
        ToolCall(tool_name="read_secret", arguments={}),
        known_capabilities=(Capability.CREDENTIAL_ACCESS,),
    )
    shell_decision = policy.evaluate(
        ToolCall(tool_name="run_command", arguments={"command": "git status"}),
        known_capabilities=(Capability.SHELL_EXECUTION,),
    )

    assert credential_decision.decision == Decision.DENY
    assert shell_decision.decision == Decision.REQUIRE_APPROVAL


def test_ci_agent_pack_gates_file_mutation(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text(render_policy_pack("ci-agent"), encoding="utf-8")
    policy = load_policy(str(path))

    decision = policy.evaluate(
        ToolCall(tool_name="write_file", arguments={"path": "README.md"}),
        known_capabilities=(Capability.FILESYSTEM_WRITE,),
    )

    assert decision.decision == Decision.REQUIRE_APPROVAL


def test_unknown_policy_pack_raises_clear_error() -> None:
    try:
        get_policy_pack("unknown")
    except ValueError as exc:
        assert "Available packs" in str(exc)
    else:
        raise AssertionError("expected ValueError")
