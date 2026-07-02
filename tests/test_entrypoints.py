from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path

import agentguard


REPO_ROOT = Path(__file__).resolve().parents[1]


def test_package_version_matches_pyproject() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert agentguard.__version__ == pyproject["project"]["version"]


def test_python_module_entrypoint_reports_version() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT)

    process = subprocess.run(  # noqa: S603 - explicit argv, no shell.
        [sys.executable, "-m", "agentguard", "--version"],
        cwd=REPO_ROOT,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=5,
        check=False,
    )

    assert process.returncode == 0
    assert process.stdout.strip().startswith("agentguard ")
