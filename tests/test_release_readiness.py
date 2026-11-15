from __future__ import annotations

import tomllib
from pathlib import Path

from decisionlock import __version__

REPO_ROOT = Path(__file__).resolve().parents[1]


def test_release_trust_files_exist() -> None:
    expected = [
        "CHANGELOG.md",
        ".github/CONTRIBUTING.md",
        "LICENSE",
        ".github/SECURITY.md",
        "docs/RELEASE.md",
    ]

    for relative_path in expected:
        path = REPO_ROOT / relative_path
        assert path.exists(), f"missing {relative_path}"
        assert path.read_text(encoding="utf-8").strip(), f"{relative_path} is empty"


def test_license_metadata_matches_license_file() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    license_text = (REPO_ROOT / "LICENSE").read_text(encoding="utf-8")

    assert pyproject["project"]["license"] == "MIT"
    assert "MIT License" in license_text
    assert "Mohammad Atashi" in license_text


def test_project_urls_expose_trust_documents() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    urls = pyproject["project"]["urls"]

    assert urls["Repository"].endswith("/TensorScholar/decisionlock")
    assert urls["Changelog"].endswith("/CHANGELOG.md")
    assert urls["Security"].endswith("/.github/SECURITY.md")


def test_runtime_entrypoints_are_packaged() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    scripts = pyproject["project"]["scripts"]
    assert scripts["decisionlock"] == "decisionlock.cli:entrypoint"
    assert scripts["decisionlock-mcp-http"] == "decisionlock.http_cli:entrypoint"
    assert scripts["decisionlock-reconcile"] == "decisionlock.reconcile_cli:entrypoint"
    assert (
        scripts["decisionlock-reconcile-worker"] == "decisionlock.reconcile_worker_cli:entrypoint"
    )


def test_release_docs_follow_runtime_version() -> None:
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    deployment = (REPO_ROOT / "docs" / "production-deployment.md").read_text(encoding="utf-8")
    assert f"v{__version__}" in readme
    assert f"decisionlock:{__version__}" in deployment


def test_dependency_audit_exception_is_retired() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "security.yml").read_text(encoding="utf-8")
    constraints = (REPO_ROOT / "requirements" / "runtime-validated.txt").read_text(encoding="utf-8")
    assert "--ignore-vuln PYSEC-2026-3552" not in workflow
    assert "cryptography==50.0.1" in constraints


def test_github_action_uploads_findings_and_summary() -> None:
    workflow = (REPO_ROOT / ".github" / "workflows" / "decisionlock.yml").read_text(
        encoding="utf-8"
    )

    assert "decisionlock-findings.json" in workflow
    assert "decisionlock-summary.md" in workflow
    assert "GITHUB_STEP_SUMMARY" in workflow


def test_real_mcp_smoke_pin_matches_release_documentation() -> None:
    smoke = (REPO_ROOT / "tests" / "test_mcp_real_server_smoke.py").read_text(encoding="utf-8")
    release = (REPO_ROOT / "docs" / "RELEASE.md").read_text(encoding="utf-8")

    assert 'FILESYSTEM_VERSION = "2026.1.14"' in smoke
    assert "@modelcontextprotocol/server-filesystem@2026.1.14" in release
    assert "2025.8.21" not in smoke + release


def test_sbom_generator_emits_current_cyclonedx(tmp_path: Path) -> None:
    import json
    import os
    import subprocess
    import sys

    output = tmp_path / "sbom.cdx.json"
    environment = dict(os.environ, SOURCE_DATE_EPOCH="1700000000")
    subprocess.run(
        [sys.executable, str(REPO_ROOT / "scripts" / "generate_sbom.py"), "--output", str(output)],
        check=True,
        cwd=REPO_ROOT,
        env=environment,
    )
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["bomFormat"] == "CycloneDX"
    assert payload["specVersion"] == "1.6"
    assert payload["metadata"]["component"]["version"] == __version__
    assert {component["name"] for component in payload["components"]} >= {
        "cryptography",
        "pydantic",
        "PyYAML",
    }
