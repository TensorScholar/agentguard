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


def test_console_script_routes_through_public_entrypoint() -> None:
    pyproject = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    assert pyproject["project"]["scripts"]["agentguard"] == "agentguard.cli:entrypoint"


def test_public_mcp_proxy_refuses_without_starting_target(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(REPO_ROOT / "src")
    marker = tmp_path / "server-started"
    policy = tmp_path / "policy.yaml"
    policy.write_text("default_action: allow\n", encoding="utf-8")
    server_code = (
        f"from pathlib import Path; Path({str(marker)!r}).write_text('started', encoding='utf-8')"
    )

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "agentguard",
            "mcp-proxy",
            "--policy",
            str(policy),
            "--",
            sys.executable,
            "-c",
            server_code,
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
        timeout=5,
        check=False,
    )

    assert process.returncode == 2
    assert process.stdout == ""
    assert "MCP execution refused" in process.stderr
    assert "agentguard legacy-mcp-proxy" in process.stderr
    assert not marker.exists()
