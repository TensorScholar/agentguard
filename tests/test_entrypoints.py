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
    env["PYTHONPATH"] = str(REPO_ROOT / "src")

    process = subprocess.run(
        [sys.executable, "-m", "agentguard", "--version"],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )

    assert process.returncode == 0
    assert process.stdout.strip().startswith("agentguard ")


def test_entrypoint_mcp_posture_exit_codes() -> None:
    from agentguard.cli import entrypoint

    bypass_code = entrypoint(
        [
            "mcp-posture",
            "--config",
            str(REPO_ROOT / "examples/mcp_posture_bypass.json"),
            "--fail-on-bypass",
        ]
    )
    assert bypass_code != 0

    protected_code = entrypoint(
        [
            "mcp-posture",
            "--config",
            str(REPO_ROOT / "examples/mcp_posture_protected.json"),
            "--fail-on-bypass",
        ]
    )
    assert protected_code == 0


def test_python_module_entrypoint_mcp_posture_exit_codes() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT / "src")

    bypass_proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "agentguard",
            "mcp-posture",
            "--config",
            str(REPO_ROOT / "examples/mcp_posture_bypass.json"),
            "--fail-on-bypass",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert bypass_proc.returncode != 0

    protected_proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "agentguard",
            "mcp-posture",
            "--config",
            str(REPO_ROOT / "examples/mcp_posture_protected.json"),
            "--fail-on-bypass",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )
    assert protected_proc.returncode == 0
