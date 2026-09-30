"""Every shipped example policy must fail closed.

An example policy is copied. If an example is default-allow, a user who
copies it inherits an allow-by-default control surface, which is the
opposite of the project's stated default-deny posture.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from agentguard.models import Decision, ToolCall
from agentguard.policy import load_policy
from agentguard.policy_packs import available_policy_packs, render_policy_pack

_REPO_ROOT = Path(__file__).parents[1]
_V1_EXAMPLE_POLICIES = sorted(
    [*(_REPO_ROOT / "examples").glob("*.yaml"), *(_REPO_ROOT / "examples").glob("*.yml")]
)
_V2_EXAMPLE_POLICIES = sorted((_REPO_ROOT / "examples").glob("*/policy.yaml"))

# A tool name that is not in any shipped example allowlist.
UNMATCHED_TOOL = ToolCall(tool_name="__agentguard_unmatched_probe__", arguments={})


def _load_v1(path: Path) -> Decision:
    return load_policy(str(path)).evaluate(UNMATCHED_TOOL).decision


def test_v1_example_policies_are_discovered() -> None:
    assert _V1_EXAMPLE_POLICIES, "expected at least one shipped v1 example policy"


@pytest.mark.parametrize("path", _V1_EXAMPLE_POLICIES, ids=lambda p: p.name)
def test_v1_example_policy_denies_unmatched_action(path: Path) -> None:
    assert _load_v1(path) == Decision.DENY


@pytest.mark.parametrize("name", available_policy_packs())
def test_policy_pack_denies_unmatched_action(name: str, tmp_path: Path) -> None:
    path = tmp_path / f"{name}.yaml"
    path.write_text(render_policy_pack(name), encoding="utf-8")

    assert load_policy(str(path)).evaluate(UNMATCHED_TOOL).decision == Decision.DENY


@pytest.mark.parametrize("name", available_policy_packs())
def test_policy_pack_has_non_empty_allowlist(name: str) -> None:
    # The v1 allowlist is the load-bearing control: it is checked first and
    # denies any tool it does not name, regardless of default_action.
    rendered = render_policy_pack(name)

    assert "allowed_tools:" in rendered


def test_v1_loader_defaults_to_deny_when_key_absent(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    path.write_text("redact_secret_outputs: true\n", encoding="utf-8")

    assert _load_v1(path) == Decision.DENY


def test_shipped_example_policies_are_not_bare_allow_defaults() -> None:
    # A shipped policy that allows everything (no allowlist, allow default) is
    # the fail-open footgun. Each example must either deny by default or carry
    # an explicit allowlist that denies every unmatched tool.
    for path in _V1_EXAMPLE_POLICIES:
        text = path.read_text(encoding="utf-8")
        if "default_action: allow" in text:
            assert "allowed_tools:" in text, path


@pytest.mark.parametrize("path", _V2_EXAMPLE_POLICIES, ids=lambda p: p.parent.name)
def test_v2_example_policy_declares_deny_default(path: Path) -> None:
    document = json.loads(json.dumps(load_policy_v2_document(path)))

    assert document["defaults"]["effect"] == "deny"


def load_policy_v2_document(path: Path) -> dict[str, object]:
    import yaml

    raw = yaml.safe_load(path.read_text(encoding="utf-8"))

    assert isinstance(raw, dict)

    return raw
