from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from agentguard.audit import AuditLedger
from agentguard.mcp_stdio import APPROVAL_REQUIRED
from agentguard.models import Decision


REAL_MCP_SMOKE_ENV = "AGENTGUARD_RUN_REAL_MCP_SMOKE"
FILESYSTEM_PACKAGE = "@modelcontextprotocol/server-filesystem"
FILESYSTEM_VERSION = "2026.1.14"

pytestmark = pytest.mark.skipif(
    os.environ.get(REAL_MCP_SMOKE_ENV) != "1",
    reason=f"set {REAL_MCP_SMOKE_ENV}=1 to run the real MCP filesystem smoke test",
)


def test_mcp_proxy_with_pinned_filesystem_server(tmp_path: Path) -> None:
    node = shutil.which("node")
    npm = shutil.which("npm")
    if node is None or npm is None:
        pytest.skip("node and npm are required for the real MCP filesystem smoke test")

    repo_root = Path(__file__).resolve().parents[1]
    install_dir = tmp_path / "npm-prefix"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    readable_file = workspace / "allowed.txt"
    blocked_file = workspace / "blocked.txt"
    readable_file.write_text("hello from pinned MCP filesystem server\n", encoding="utf-8")

    env = os.environ.copy()
    env["PYTHONPATH"] = _prepend_pythonpath(repo_root, env.get("PYTHONPATH"))
    env["npm_config_cache"] = str(tmp_path / "npm-cache")

    install = subprocess.run(  # noqa: S603 - test uses explicit argv only.
        [
            npm,
            "install",
            "--prefix",
            str(install_dir),
            f"{FILESYSTEM_PACKAGE}@{FILESYSTEM_VERSION}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=120,
        check=False,
        env=env,
    )
    assert install.returncode == 0, _process_output(install)

    server_index = (
        install_dir
        / "node_modules"
        / "@modelcontextprotocol"
        / "server-filesystem"
        / "dist"
        / "index.js"
    )
    assert server_index.exists()

    policy_path = tmp_path / "policy.yaml"
    ledger_path = tmp_path / "audit.sqlite"
    policy_path.write_text(
        "\n".join(
            [
                "denied_capabilities:",
                "  - credential_access",
                "require_approval_capabilities:",
                "  - filesystem_write",
                "  - shell_execution",
                "  - production_mutation",
                "",
            ]
        ),
        encoding="utf-8",
    )

    payload = _jsonl(
        [
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2025-03-26",
                    "capabilities": {},
                    "clientInfo": {"name": "agentguard-smoke", "version": "0.1.0"},
                },
            },
            {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
            {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}},
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "read_text_file",
                    "arguments": {"path": str(readable_file)},
                },
            },
            {
                "jsonrpc": "2.0",
                "id": 4,
                "method": "tools/call",
                "params": {
                    "name": "write_file",
                    "arguments": {"path": str(blocked_file), "content": "blocked"},
                },
            },
        ]
    )

    process = subprocess.run(  # noqa: S603 - test uses explicit argv only.
        [
            sys.executable,
            "-m",
            "agentguard.cli",
            "mcp-proxy",
            "--policy",
            str(policy_path),
            "--ledger",
            str(ledger_path),
            "--shutdown-timeout-seconds",
            "1.0",
            "--",
            node,
            str(server_index),
            str(workspace),
        ],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=20,
        check=False,
        cwd=repo_root,
        env=env,
    )
    assert process.returncode == 0, _process_output(process)

    responses = [json.loads(line) for line in process.stdout.decode("utf-8").splitlines()]
    responses_by_id = {response["id"]: response for response in responses if "id" in response}
    ledger = AuditLedger(ledger_path)
    tools = ledger.list_tool_inventory()
    events = ledger.list_events()

    assert set(responses_by_id) == {1, 2, 3, 4}
    assert responses_by_id[1]["result"]["serverInfo"]["name"] == "secure-filesystem-server"
    assert _tool_names(responses_by_id[2]) >= {"read_text_file", "write_file"}
    assert responses_by_id[3]["result"]["content"][0]["text"] == readable_file.read_text(
        encoding="utf-8"
    )
    assert responses_by_id[4]["error"]["code"] == APPROVAL_REQUIRED
    assert responses_by_id[4]["error"]["data"]["rule_id"] == "capability.requires_approval"
    assert not blocked_file.exists()
    assert {tool.name for tool in tools} >= {"read_text_file", "write_file"}
    assert [(event.tool_name, event.decision) for event in events] == [
        ("read_text_file", Decision.ALLOW),
        ("write_file", Decision.REQUIRE_APPROVAL),
    ]


def _jsonl(messages: list[dict[str, object]]) -> bytes:
    return ("\n".join(json.dumps(message) for message in messages) + "\n").encode("utf-8")


def _tool_names(tools_list_response: dict[str, object]) -> set[str]:
    result = tools_list_response.get("result")
    if not isinstance(result, dict):
        return set()
    tools = result.get("tools")
    if not isinstance(tools, list):
        return set()
    return {str(tool.get("name")) for tool in tools if isinstance(tool, dict)}


def _prepend_pythonpath(repo_root: Path, existing: str | None) -> str:
    if not existing:
        return str(repo_root)
    return str(repo_root) + os.pathsep + existing


def _process_output(process: subprocess.CompletedProcess[bytes]) -> str:
    stdout = process.stdout.decode("utf-8", errors="replace")
    stderr = process.stderr.decode("utf-8", errors="replace")
    return f"stdout:\n{stdout}\n\nstderr:\n{stderr}"
