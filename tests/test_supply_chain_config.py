"""CI and CodeQL guard rails.

These assert configuration facts that are easy to silently regress. In particular,
CodeQL must be able to fail a build: without security-events: write, or with
upload: never, the analyze step publishes nothing and no alert can ever gate a
merge.
"""

from __future__ import annotations

from pathlib import Path

_REPO_ROOT = Path(__file__).parents[1]


def _workflow(name: str) -> dict:
    import yaml

    path = _REPO_ROOT / ".github" / "workflows" / name
    return yaml.safe_load(path.read_text(encoding="utf-8"))


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


def test_codeql_retains_sarif_as_evidence() -> None:
    workflow = _workflow("codeql.yml")
    steps = workflow["jobs"]["analyze"]["steps"]

    assert any("upload-artifact" in str(step.get("uses", "")) for step in steps)


def test_all_workflows_parse_and_declare_permissions() -> None:
    for path in sorted((_REPO_ROOT / ".github" / "workflows").glob("*.yml")):
        workflow = _workflow(path.name)
        assert workflow.get("jobs"), path.name
        assert "permissions" in workflow, f"{path.name} must declare explicit permissions"
        assert workflow["permissions"].get("contents") == "read", (
            f"{path.name} must not request write access to contents"
        )
