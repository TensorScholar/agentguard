from __future__ import annotations

import tomllib
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_release_trust_files_exist() -> None:
    expected = [
        "CHANGELOG.md",
        "CONTRIBUTING.md",
        "LICENSE",
        "SECURITY.md",
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

    assert urls["Repository"].endswith("/TensorScholar/agentguard")
    assert urls["Changelog"].endswith("/CHANGELOG.md")
    assert urls["Security"].endswith("/SECURITY.md")
