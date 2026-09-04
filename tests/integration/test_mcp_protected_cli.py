from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import yaml

from agentguard.adapters.crypto import Ed25519Signer
from agentguard.adapters.storage.sqlite import SQLiteState
from agentguard.cli import _V1_ONLY_COMMANDS
from agentguard.domain import Effect, ExecutionState, PolicyDocument, ProvenanceLabel
from agentguard.domain.policy import (
    ActionMatcher,
    PolicyDefaults,
    PolicyMetadata,
    PolicyRule,
    ProvenanceMatcher,
)


def policy() -> PolicyDocument:
    provenance = ProvenanceMatcher(contains_any=frozenset({ProvenanceLabel.UNVERIFIED}))
    return PolicyDocument(
        metadata=PolicyMetadata(id="mcp-v2-cli", revision=1),
        defaults=PolicyDefaults(),
        rules=(
            PolicyRule(
                id="read",
                priority=100,
                effect=Effect.ALLOW,
                action=ActionMatcher(tools=frozenset({"read_file"})),
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


def test_legacy_mcp_proxy_route_remains_v1_and_v2_is_explicit() -> None:
    assert "mcp-proxy" in _V1_ONLY_COMMANDS
    assert "mcp-proxy-v2" not in _V1_ONLY_COMMANDS


def test_explicit_v2_cli_executes_allowed_call_and_blocks_write(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[2]
    key = tmp_path / "decision-private.pem"
    Ed25519Signer.generate().save_private(key)
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(
        yaml.safe_dump(policy().model_dump(mode="json"), sort_keys=False),
        encoding="utf-8",
    )
    state_path = tmp_path / "action-integrity.sqlite"
    server_log = tmp_path / "server-calls.jsonl"
    server_script = tmp_path / "server.py"
    server_script.write_text(
        """
import json
import pathlib
import sys

log = pathlib.Path(sys.argv[1])
for raw in sys.stdin:
    msg = json.loads(raw)
    method = msg.get("method")
    if method == "initialize":
        response = {
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                "protocolVersion": "2025-03-26",
                "capabilities": {"tools": {"listChanged": True}},
                "serverInfo": {"name": "fake", "version": "1"},
            },
        }
    elif method == "tools/list":
        response = {
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {
                "tools": [
                    {"name": "read_file", "inputSchema": {"type": "object"}},
                    {"name": "write_file", "inputSchema": {"type": "object"}},
                ]
            },
        }
    elif method == "tools/call":
        with log.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(msg, sort_keys=True) + "\\n")
        response = {
            "jsonrpc": "2.0",
            "id": msg["id"],
            "result": {"content": [{"type": "text", "text": "provider-output"}]},
        }
    else:
        continue
    sys.stdout.write(json.dumps(response) + "\\n")
    sys.stdout.flush()
""".strip()
        + "\n",
        encoding="utf-8",
    )
    env = os.environ.copy()
    env["PYTHONPATH"] = str(repo_root / "src") + os.pathsep + env.get("PYTHONPATH", "")
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
            "fake-filesystem",
            "--shutdown-timeout-seconds",
            "0.2",
            "--",
            sys.executable,
            str(server_script),
            str(server_log),
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
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {"name": "test", "version": "1"},
            },
        }
    )
    assert initialized["result"]["protocolVersion"] == "2025-03-26"
    exchange(
        {"jsonrpc": "2.0", "method": "notifications/initialized", "params": {}},
        expect_response=False,
    )
    tools = exchange({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    assert {tool["name"] for tool in tools["result"]["tools"]} == {
        "read_file",
        "write_file",
    }
    allowed = exchange(
        {
            "jsonrpc": "2.0",
            "id": 3,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "README.md"}},
        }
    )
    assert allowed["id"] == 3
    assert allowed["result"]["content"][0]["text"] == "provider-output"
    blocked = exchange(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "write_file", "arguments": {"path": "x"}},
        }
    )
    assert blocked["id"] == 4
    assert "requires approval" in blocked["error"]["message"]
    process.stdin.close()
    assert process.wait(timeout=5) == 0

    calls = [json.loads(line) for line in server_log.read_text(encoding="utf-8").splitlines()]
    assert len(calls) == 1
    assert calls[0]["params"]["name"] == "read_file"
    assert str(calls[0]["id"]).startswith("exec_")
    records = SQLiteState(state_path).list_executions()
    assert len(records) == 1
    assert records[0].state == ExecutionState.SUCCEEDED
