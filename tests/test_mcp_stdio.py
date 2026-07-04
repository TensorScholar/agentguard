from __future__ import annotations

import io
import json
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from agentguard.audit import AuditLedger
from agentguard.mcp_stdio import (
    APPROVAL_REQUIRED,
    POLICY_DENIED,
    MCPMessageProcessor,
    _iter_bounded_lines,
    _write_and_flush,
)
from agentguard.models import Capability, Decision, RiskLevel, ToolInventoryItem
from agentguard.policy import Policy


def _loads(payload: bytes) -> dict:
    return json.loads(payload.decode("utf-8"))


def test_tools_list_passes_through() -> None:
    processor = MCPMessageProcessor(policy=Policy())
    line = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n'

    action = processor.handle_client_line(line)

    assert action.to_server == line
    assert action.to_client is None


def test_tools_list_response_records_inventory(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.upsert_tool_inventory([ToolInventoryItem(source="mcp_stdio", name="old_tool")])
    processor = MCPMessageProcessor(policy=Policy(), ledger=ledger)

    processor.handle_client_line(b'{"jsonrpc":"2.0","id":11,"method":"tools/list","params":{}}\n')
    action = processor.handle_server_line(
        b'{"jsonrpc":"2.0","id":11,"result":{"tools":[{"name":"write_file",'
        b'"description":"Write content to a path","inputSchema":{"type":"object",'
        b'"properties":{"path":{"type":"string"}}}}]}}\n'
    )
    response = _loads(action.to_client or b"{}")
    tools = ledger.list_tool_inventory()

    assert response["result"]["tools"][0]["name"] == "write_file"
    assert len(tools) == 1
    assert tools[0].name == "write_file"
    assert tools[0].risk_level.value == "high"
    assert "filesystem_write" in [capability.value for capability in tools[0].capabilities]


def test_denied_tool_call_returns_error_and_does_not_forward(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    processor = MCPMessageProcessor(policy=Policy(), ledger=ledger)
    line = (
        b'{"jsonrpc":"2.0","id":2,"method":"tools/call",'
        b'"params":{"name":"read_file","arguments":{"path":".env"}}}\n'
    )

    action = processor.handle_client_line(line)
    response = _loads(action.to_client or b"{}")

    assert action.to_server is None
    assert response["error"]["code"] == POLICY_DENIED
    assert response["error"]["data"]["rule_id"] == "path.sensitive"
    assert ledger.list_events()[0].decision == Decision.DENY


def test_approval_required_tool_call_returns_error() -> None:
    processor = MCPMessageProcessor(policy=Policy())
    line = (
        b'{"jsonrpc":"2.0","id":"abc","method":"tools/call",'
        b'"params":{"name":"run_command","arguments":{"command":"git status"}}}\n'
    )

    action = processor.handle_client_line(line)
    response = _loads(action.to_client or b"{}")

    assert action.to_server is None
    assert response["error"]["code"] == APPROVAL_REQUIRED


def test_allowed_call_is_correlated_and_response_is_redacted(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    processor = MCPMessageProcessor(policy=Policy(), ledger=ledger)
    call_line = (
        b'{"jsonrpc":"2.0","id":3,"method":"tools/call",'
        b'"params":{"name":"read_file","arguments":{"path":"README.md"}}}\n'
    )

    call_action = processor.handle_client_line(call_line)
    response_action = processor.handle_server_line(
        b'{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text",'
        b'"text":"OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz"}]}}\n'
    )
    response = _loads(response_action.to_client or b"{}")
    events = ledger.list_events()

    assert call_action.to_server == call_line
    assert "sk-abcdefghijklmnopqrstuvwxyz" not in json.dumps(response)
    assert response["result"]["content"][0]["text"] == "OPENAI_API_KEY=[REDACTED:openai_key]"
    assert [event.decision for event in events] == [Decision.ALLOW, Decision.REDACT]


def test_discovered_capability_can_deny_tool_call(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.upsert_tool_inventory(
        [
            ToolInventoryItem(
                source="mcp_stdio",
                name="read_secret",
                capabilities=(Capability.CREDENTIAL_ACCESS,),
                risk_level=RiskLevel.CRITICAL,
                reasons=("tool reads credentials",),
            )
        ]
    )
    processor = MCPMessageProcessor(
        policy=Policy(denied_capabilities=(Capability.CREDENTIAL_ACCESS,)),
        ledger=ledger,
    )
    line = (
        b'{"jsonrpc":"2.0","id":12,"method":"tools/call",'
        b'"params":{"name":"read_secret","arguments":{}}}\n'
    )

    action = processor.handle_client_line(line)
    response = _loads(action.to_client or b"{}")

    assert action.to_server is None
    assert response["error"]["code"] == POLICY_DENIED
    assert response["error"]["data"]["rule_id"] == "capability.denied"


def test_stale_inventory_requires_approval_for_vague_tool_name(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.upsert_tool_inventory(
        [
            ToolInventoryItem(
                source="mcp_stdio",
                name="invoke",
                capabilities=(Capability.DATABASE_ACCESS,),
                risk_level=RiskLevel.HIGH,
                reasons=("tool metadata mentions database access",),
                discovered_at=datetime.now(timezone.utc) - timedelta(seconds=30),
            )
        ]
    )
    processor = MCPMessageProcessor(
        policy=Policy(),
        ledger=ledger,
        inventory_ttl_seconds=1,
    )
    line = (
        b'{"jsonrpc":"2.0","id":14,"method":"tools/call",'
        b'"params":{"name":"invoke","arguments":{}}}\n'
    )

    action = processor.handle_client_line(line)
    response = _loads(action.to_client or b"{}")
    events = ledger.list_events()

    assert action.to_server is None
    assert response["error"]["code"] == APPROVAL_REQUIRED
    assert response["error"]["data"]["rule_id"] == "inventory.stale"
    assert response["error"]["data"]["capabilities"] == ["database_access"]
    assert [(event.decision, event.rule_id) for event in events] == [
        (Decision.REQUIRE_APPROVAL, "inventory.stale")
    ]


def test_stale_inventory_preserves_fallback_hard_deny(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.upsert_tool_inventory(
        [
            ToolInventoryItem(
                source="mcp_stdio",
                name="read_file",
                capabilities=(Capability.FILESYSTEM_READ,),
                discovered_at=datetime.now(timezone.utc) - timedelta(seconds=30),
            )
        ]
    )
    processor = MCPMessageProcessor(policy=Policy(), ledger=ledger, inventory_ttl_seconds=1)
    line = (
        b'{"jsonrpc":"2.0","id":15,"method":"tools/call",'
        b'"params":{"name":"read_file","arguments":{"path":".env"}}}\n'
    )

    action = processor.handle_client_line(line)
    response = _loads(action.to_client or b"{}")

    assert action.to_server is None
    assert response["error"]["code"] == POLICY_DENIED
    assert response["error"]["data"]["rule_id"] == "path.sensitive"


def test_inventory_ttl_zero_disables_expiry(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.upsert_tool_inventory(
        [
            ToolInventoryItem(
                source="mcp_stdio",
                name="invoke",
                capabilities=(Capability.CREDENTIAL_ACCESS,),
                risk_level=RiskLevel.CRITICAL,
                reasons=("tool metadata mentions credentials",),
                discovered_at=datetime.now(timezone.utc) - timedelta(days=365),
            )
        ]
    )
    processor = MCPMessageProcessor(
        policy=Policy(denied_capabilities=(Capability.CREDENTIAL_ACCESS,)),
        ledger=ledger,
        inventory_ttl_seconds=0,
    )
    line = (
        b'{"jsonrpc":"2.0","id":16,"method":"tools/call",'
        b'"params":{"name":"invoke","arguments":{}}}\n'
    )

    action = processor.handle_client_line(line)
    response = _loads(action.to_client or b"{}")

    assert action.to_server is None
    assert response["error"]["code"] == POLICY_DENIED
    assert response["error"]["data"]["rule_id"] == "capability.denied"


def test_unknown_inventory_falls_back_to_tool_name_classification() -> None:
    processor = MCPMessageProcessor(policy=Policy())
    line = (
        b'{"jsonrpc":"2.0","id":13,"method":"tools/call",'
        b'"params":{"name":"run_command","arguments":{"command":"pwd"}}}\n'
    )

    action = processor.handle_client_line(line)
    response = _loads(action.to_client or b"{}")

    assert action.to_server is None
    assert response["error"]["code"] == APPROVAL_REQUIRED


def test_malformed_client_message_fails_closed() -> None:
    processor = MCPMessageProcessor(policy=Policy())

    action = processor.handle_client_line(b"{bad json}\n")
    response = _loads(action.to_client or b"{}")

    assert action.to_server is None
    assert response["error"]["code"] == -32700


def test_bounded_line_reader_rejects_oversized_line() -> None:
    import io

    stream = io.BytesIO(b"abcdef\nok\n")
    lines = list(_iter_bounded_lines(stream, max_bytes=3))

    assert lines == [None, b"ok\n"]


def test_bounded_line_reader_rejects_newline_terminated_oversized_line() -> None:
    import io

    stream = io.BytesIO(b"abc\nok\n")
    lines = list(_iter_bounded_lines(stream, max_bytes=3))

    assert lines == [None, b"ok\n"]


def test_write_and_flush_returns_false_for_closed_downstream() -> None:
    class ClosedOutput(io.BytesIO):
        def write(self, payload: bytes) -> int:
            raise BrokenPipeError

        def flush(self) -> None:
            raise AssertionError("flush should not run after write fails")

    assert _write_and_flush(ClosedOutput(), b"payload") is False


def test_mcp_proxy_integrates_with_stdio_server(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    ledger_path = tmp_path / "audit.sqlite"
    fake_server = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"
    policy_path.write_text(
        "\n".join(
            [
                "denied_capabilities:",
                "  - credential_access",
                "require_approval_capabilities:",
                "  - shell_execution",
                "  - production_mutation",
            ]
        ),
        encoding="utf-8",
    )
    payload = "\n".join(
        [
            json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}}),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {
                        "name": "echo",
                        "arguments": {
                            "text": "OPENAI_API_KEY=sk-integrationtestabcdefghijklmnopqrstuvwxyz"
                        },
                    },
                }
            ),
            json.dumps(
                {
                    "jsonrpc": "2.0",
                    "id": 3,
                    "method": "tools/call",
                    "params": {"name": "read_secret", "arguments": {}},
                }
            ),
            "",
        ]
    ).encode("utf-8")

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
            "0.5",
            "--",
            sys.executable,
            str(fake_server),
        ],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
        check=False,
    )
    responses = [json.loads(line) for line in process.stdout.decode("utf-8").splitlines()]
    ledger = AuditLedger(ledger_path)

    assert process.returncode == 0, process.stderr.decode("utf-8")
    responses_by_id = {response["id"]: response for response in responses}
    assert set(responses_by_id) == {1, 2, 3}
    assert responses_by_id[1]["result"]["tools"][1]["name"] == "read_secret"
    assert (
        responses_by_id[2]["result"]["content"][0]["text"]
        == "OPENAI_API_KEY=[REDACTED:openai_key]"
    )
    assert responses_by_id[3]["error"]["code"] == POLICY_DENIED
    assert responses_by_id[3]["error"]["data"]["rule_id"] == "capability.denied"
    assert {tool.name for tool in ledger.list_tool_inventory()} >= {"echo", "read_secret"}
    assert [event.decision for event in ledger.list_events()] == [
        Decision.ALLOW,
        Decision.REDACT,
        Decision.DENY,
    ]


def test_mcp_proxy_drains_high_volume_server_output(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit.sqlite"
    fake_server = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"
    burst_count = 600
    payload = (
        json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {"name": "burst", "arguments": {}},
            }
        )
        + "\n"
    ).encode("utf-8")

    process = subprocess.run(  # noqa: S603 - test uses explicit argv only.
        [
            sys.executable,
            "-m",
            "agentguard.cli",
            "mcp-proxy",
            "--ledger",
            str(ledger_path),
            "--shutdown-timeout-seconds",
            "0.5",
            "--",
            sys.executable,
            str(fake_server),
            "--burst-count",
            str(burst_count),
            "--burst-bytes",
            "512",
        ],
        input=payload,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=10,
        check=False,
    )
    responses = [json.loads(line) for line in process.stdout.decode("utf-8").splitlines()]
    ledger = AuditLedger(ledger_path)
    progress_messages = [
        response for response in responses if response.get("method") == "notifications/progress"
    ]
    final_response = responses[-1]

    assert process.returncode == 0, process.stderr.decode("utf-8")
    assert len(responses) == burst_count + 1
    assert len(progress_messages) == burst_count
    assert progress_messages[0]["params"]["index"] == 0
    assert progress_messages[-1]["params"]["index"] == burst_count - 1
    assert final_response["id"] == 21
    assert final_response["result"]["content"][0]["text"] == f"burst:{burst_count}"
    assert [(event.tool_name, event.decision) for event in ledger.list_events()] == [
        ("burst", Decision.ALLOW)
    ]


def test_mcp_proxy_terminates_server_that_ignores_stdin_eof(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit.sqlite"
    fake_server = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"

    process = subprocess.run(  # noqa: S603 - test uses explicit argv only.
        [
            sys.executable,
            "-m",
            "agentguard.cli",
            "mcp-proxy",
            "--ledger",
            str(ledger_path),
            "--shutdown-timeout-seconds",
            "0.1",
            "--",
            sys.executable,
            str(fake_server),
            "--ignore-eof",
        ],
        input=b"",
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
        check=False,
    )

    assert process.returncode != 0
    assert process.stdout == b""
