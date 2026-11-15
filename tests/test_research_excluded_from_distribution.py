"""The research program must not ship inside the product distribution.

``decisionlock.research`` is the pre-registered authorization-lineage experiment
retained as the project's research record. Its result is
``RESEARCH_CLAIM: NOT_VALIDATED`` and
``DECISIONLOCK_SPECIFIC_DIFFERENTIATION_THESIS: FALSIFIED_WITHIN_PROTOCOL`` (see
docs/research/FREEZE_V2_RESULT_ADJUDICATION.md), so it must not be packaged as
part of the distributed runtime.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).parents[1]


def _pyproject() -> dict:
    return tomllib.loads((_REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))


def test_research_package_is_excluded_from_distribution() -> None:
    exclude = _pyproject()["tool"]["setuptools"]["packages"]["find"]["exclude"]

    assert "decisionlock.research*" in exclude


def test_research_package_is_present_in_source_checkout() -> None:
    # The record must be retained in the repository; only its distribution is
    # removed. If this fails the exclusion above has also deleted evidence.
    assert (_REPO_ROOT / "src" / "decisionlock" / "research" / "__init__.py").exists()


def test_research_directory_is_substantial_enough_to_matter() -> None:
    research = _REPO_ROOT / "src" / "decisionlock" / "research"
    modules = list(research.rglob("*.py"))
    total = sum(len(path.read_text(encoding="utf-8").splitlines()) for path in modules)

    assert len(modules) > 5
    assert total > 1000


@pytest.mark.parametrize(
    "path",
    [
        "src/decisionlock/__init__.py",
        "src/decisionlock/engine/execution.py",
        "src/decisionlock/application/service.py",
        "src/decisionlock/policy.py",
    ],
)
def test_product_modules_do_not_import_research(path: str) -> None:
    text = (_REPO_ROOT / path).read_text(encoding="utf-8")
    lines = [
        line
        for line in text.splitlines()
        if "research" in line and not line.strip().startswith(("#", '"', "*"))
    ]
    assert lines == [], f"{path} imports the research package: {lines}"
