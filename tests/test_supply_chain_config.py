"""Supply-chain guard rails for the Phase 0 stabilization.

These assert the configuration facts that are easy to silently regress:
Dependabot is enabled, the build backend is hash-pinned and matches
pyproject, and CodeQL can actually fail a build.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

_REPO_ROOT = Path(__file__).parents[1]


def _dependabot() -> dict:
    import yaml

    return yaml.safe_load((_REPO_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))


def _workflow(name: str) -> dict:
    import yaml

    path = _REPO_ROOT / ".github" / "workflows" / name
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_dependabot_is_enabled_for_pip_and_actions() -> None:
    updates = _dependabot()["updates"]
    ecosystems = {entry["package-ecosystem"] for entry in updates}

    assert ecosystems == {"pip", "github-actions"}
    for entry in updates:
        assert entry["open-pull-requests-limit"] > 0, entry["package-ecosystem"]


def test_dependabot_pause_is_not_still_documented() -> None:
    text = (_REPO_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")

    assert "paused" not in text.lower().replace("were paused", "")


def test_build_system_requires_exact_setuptools_pin() -> None:
    spec = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    requires = spec["build-system"]["requires"]

    assert any(re.fullmatch(r"setuptools==[0-9]+(\.[0-9]+)*", item) for item in requires), requires
    assert not any(">=" in item or "~=" in item for item in requires), requires


def test_build_hashed_requirements_uses_require_hashes() -> None:
    text = (_REPO_ROOT / "requirements" / "build-hashed.txt").read_text(encoding="utf-8")

    assert "--require-hashes" in text
    assert len(re.findall(r"--hash=sha256:[0-9a-f]{64}", text)) >= 1


def test_build_hashed_requirements_pin_every_requirement() -> None:
    text = (_REPO_ROOT / "requirements" / "build-hashed.txt").read_text(encoding="utf-8")
    # In --require-hashes mode pip requires every transitive requirement to be
    # pinned and hashed; a missing transitive pin breaks the install.
    entries = [
        line
        for line in text.splitlines()
        if line and not line.startswith(("#", "-", " ")) and "==" in line
    ]
    hashes = re.findall(r"--hash=sha256:[0-9a-f]{64}", text)

    assert len(entries) >= 2
    assert len(hashes) >= len(entries)


def test_build_hashed_setuptools_matches_pyproject() -> None:
    spec = tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    declared = next(
        item for item in spec["build-system"]["requires"] if item.startswith("setuptools==")
    )
    text = (_REPO_ROOT / "requirements" / "build-hashed.txt").read_text(encoding="utf-8")
    pinned = re.search(r"setuptools==([0-9][0-9.]*)", text)

    assert pinned, "build-hashed.txt must pin setuptools"
    assert f"setuptools=={pinned.group(1)}" == declared


def test_codeql_can_fail_the_build() -> None:
    workflow = _workflow("codeql.yml")
    permissions = workflow["permissions"]
    steps = workflow["jobs"]["analyze"]["steps"]

    assert permissions.get("security-events") == "write", (
        "without security-events: write the analyze step cannot publish results "
        "and nothing can fail the check"
    )
    analyze = next(step for step in steps if "codeql-action/analyze" in str(step.get("uses", "")))
    assert analyze.get("continue-on-error") in (None, False)
    assert analyze.get("with", {}).get("upload") != "never", (
        "upload: never means no results are published and no alert can fail the check"
    )


def test_all_workflows_parse_and_declare_permissions() -> None:
    for path in sorted((_REPO_ROOT / ".github" / "workflows").glob("*.yml")):
        workflow = _workflow(path.name)
        assert workflow.get("jobs"), path.name
        assert "permissions" in workflow, f"{path.name} must declare explicit permissions"
        assert workflow["permissions"].get("contents") == "read", (
            f"{path.name} must not request write access to contents"
        )
