from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from agentguard.adapters.crypto import Ed25519Signer
from agentguard.adapters.storage.sqlite import SQLiteState
from agentguard.domain import Effect, ExecutionState, PolicyDocument, ProvenanceLabel
from agentguard.domain.policy import (
    ActionMatcher,
    PolicyDefaults,
    PolicyMetadata,
    PolicyRule,
    ProvenanceMatcher,
)

REAL_MCP_V2_SMOKE_ENV = "AGENTGUARD_RUN_REAL_MCP_V2_SMOKE"
FILESYSTEM_PACKAGE = "@modelcontextprotocol/server-filesystem"
FILESYSTEM_VERSION = "2026.1.14"
SUPPORTED_PROFILE = "2025-03-26"

pytestmark = pytest.mark.skipif(
    os.environ.get(REAL_MCP_V2_SMOKE_ENV) != "1",
    reason=f"set {REAL_MCP_V2_SMOKE_ENV}=1 to run the protected v2 MCP filesystem smoke test",
)


def test_protected_v2_proxy_with_pinned_filesystem_server(tmp_path: Path) -> None:
    node = shutil.which("node")
    npm = shutil.which("npm")
    if node is None or npm is None:
        pytest.skip("node and npm are required for the protected v2 MCP filesystem smoke test")

    repo_root = Path(__file__).resolve().parents[1]
    install_dir = tmp_path / "npm-prefix"
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    readable_file = workspace / "allowed.txt"
    blocked_file = workspace / "blocked.txt"
    readable_file.write_text("protected v2 hello\n", encoding="utf-8")

    env = os.environ.copy()
    env["PYTHONPATH"] = _prepend_pythonpath(repo_root / "src", env.get("PYTHONPATH"))
    env["npm_config_cache"] = str(tmp_path / "npm-cache")
    install = subprocess.run(
        [
            npm,
            "install",
            "--prefix",
            str(install_dir),
            f"{FILESYSTEM_PACKAGE}@{FILESYSTEM_VERSION}",
        ],
        capture_output=True,
        timeout=300,
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

    policy = _policy()
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(policy.model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    key = tmp_path / "decision-private.pem"
    Ed25519Signer.generate().save_private(key)
    state_path = tmp_path / "action-integrity.sqlite"

    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "agentguard.cli",
            "mcp-proxy-v2",
            "--policy",
            str(policy_path),
            "--key",
            str(key),
            "--state",
            str(state_path),
            "--server-id",
            "pinned-filesystem",
            "--execution-timeout-seconds",
            "5",
            "--shutdown-timeout-seconds",
            "1",
            "--",
            node,
            str(server_index),
            str(workspace),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        cwd=repo_root,
        env=env,
        text=True,
    )
    assert process.stdin is not None
    assert process.stdout is not None

    def exchange(message: dict[str, object], *, expect_response: bool = True):
        process.stdin.write(json.dumps(message) + "\n")
        process.stdin.flush()
        if not expect_response:
            return None
        line = process.stdout.readline()
        assert line, process.stderr.read() if process.stderr else ""
        return json.loads(line)

    initialized = exchange(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": SUPPORTED_PROFILE,
                "capabilities": {},
                "clientInfo": {"name": "agentguard-v2-smoke", "version": "0.1.0"},
            },
        }
    )
    assert initialized["result"]["protocolVersion"] == SUPPORTED_PROFILE
    exchange(
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        expect_response=False,
    )

    tools: list[dict[str, object]] = []
    cursor: str | None = None
    request_id = 2
    while True:
        params = {} if cursor is None else {"cursor": cursor}
        response = exchange(
            {"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": params}
        )
        result = response["result"]
        tools.extend(result["tools"])
        cursor = result.get("nextCursor")
        request_id += 1
        if cursor is None:
            break

    tool_names = {str(tool.get("name")) for tool in tools}
    assert {"read_text_file", "write_file"} <= tool_names

    allowed_id = request_id
    allowed = exchange(
        {
            "jsonrpc": "2.0",
            "id": allowed_id,
            "method": "tools/call",
            "params": {
                "name": "read_text_file",
                "arguments": {"path": str(readable_file)},
            },
        }
    )
    assert allowed["id"] == allowed_id

    expected_text = readable_file.read_text(encoding="utf-8")
    result = allowed["result"]
    assert isinstance(result, dict)

    content = result.get("content")
    assert isinstance(content, list)
    assert any(
        isinstance(item, dict) and item.get("type") == "text" and item.get("text") == expected_text
        for item in content
    )

    structured_content = result.get("structuredContent")
    if structured_content is not None:
        assert isinstance(structured_content, dict)
        assert structured_content.get("content") == expected_text

    blocked_id = allowed_id + 1
    blocked = exchange(
        {
            "jsonrpc": "2.0",
            "id": blocked_id,
            "method": "tools/call",
            "params": {
                "name": "write_file",
                "arguments": {"path": str(blocked_file), "content": "blocked"},
            },
        }
    )
    assert blocked["id"] == blocked_id
    assert "requires approval" in blocked["error"]["message"]
    assert not blocked_file.exists()

    process.stdin.close()
    assert process.wait(timeout=10) == 0, process.stderr.read() if process.stderr else ""
    records = SQLiteState(state_path).list_executions()
    assert len(records) == 1
    assert records[0].state == ExecutionState.SUCCEEDED


def _policy() -> PolicyDocument:
    provenance = ProvenanceMatcher(contains_any=frozenset({ProvenanceLabel.UNVERIFIED}))
    return PolicyDocument(
        metadata=PolicyMetadata(id="mcp-v2-real-smoke", revision=1),
        defaults=PolicyDefaults(),
        rules=(
            PolicyRule(
                id="read",
                priority=100,
                effect=Effect.ALLOW,
                action=ActionMatcher(tools=frozenset({"read_text_file"})),
                provenance=provenance,
            ),
            PolicyRule(
                id="write",
                priority=100,
                effect=Effect.REQUIRE_APPROVAL,
                action=ActionMatcher(tools=frozenset({"write_file"})),
                provenance=provenance,
            ),
        ),
    )


def _prepend_pythonpath(path: Path, existing: str | None) -> str:
    if not existing:
        return str(path)
    return str(path) + os.pathsep + existing


def _process_output(process: subprocess.CompletedProcess[bytes]) -> str:
    stdout = process.stdout.decode("utf-8", errors="replace")
    stderr = process.stderr.decode("utf-8", errors="replace")
    return f"stdout:\n{stdout}\n\nstderr:\n{stderr}"
