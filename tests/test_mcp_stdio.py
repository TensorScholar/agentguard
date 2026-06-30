from __future__ import annotations

import json
from pathlib import Path

from agentguard.audit import AuditLedger
from agentguard.mcp_stdio import (
    APPROVAL_REQUIRED,
    POLICY_DENIED,
    MCPMessageProcessor,
    _iter_bounded_lines,
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
        b'{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text","text":"OPENAI_API_KEY=sk-abcdefghijklmnopqrstuvwxyz"}]}}\n'
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
