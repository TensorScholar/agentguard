from __future__ import annotations

import io
import json
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from agentguard.audit import AuditLedger, hash_tool_arguments
from agentguard.mcp_stdio import (
    APPROVAL_REQUIRED,
    POLICY_DENIED,
    MCPMessageProcessor,
    MCPStdioProxy,
    _iter_bounded_lines,
    _OutputDrainState,
    _write_and_flush,
    derive_server_id,
    mcp_source_id,
)
from agentguard.models import ApprovalGrant, Capability, Decision, RiskLevel, ToolInventoryItem
from agentguard.policy import Policy

_ALLOW_POLICY_PATH = Path(__file__).parent / "fixtures" / "allow_policy.yaml"


def _permissive_policy() -> Policy:
    """Default-deny is the product default; these tests exercise stdio
    correlation, inventory and transport behaviour, not the default effect, so
    they opt in explicitly rather than relying on a fail-open default."""

    return Policy(default_action=Decision.ALLOW)


def _loads(payload: bytes) -> dict:
    return json.loads(payload.decode("utf-8"))


def test_server_identity_is_stable_and_isolates_inventory(tmp_path: Path) -> None:
    command = ["python", "server.py", "--tenant", "alpha"]
    expected = derive_server_id(command)
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    proxy = MCPStdioProxy(command, _permissive_policy(), ledger)

    assert proxy.server_id == expected
    assert proxy.processor.source == mcp_source_id(command)
    assert mcp_source_id(command, "filesystem-prod") == "mcp_stdio:filesystem-prod"


def test_tools_list_passes_through() -> None:
    processor = MCPMessageProcessor(policy=_permissive_policy())
    line = b'{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}\n'

    action = processor.handle_client_line(line)

    assert action.to_server == line
    assert action.to_client is None


def test_tools_list_response_records_inventory(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.upsert_tool_inventory([ToolInventoryItem(source="mcp_stdio", name="old_tool")])
    processor = MCPMessageProcessor(policy=_permissive_policy(), ledger=ledger)

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
    processor = MCPMessageProcessor(policy=_permissive_policy(), ledger=ledger)
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
    processor = MCPMessageProcessor(policy=_permissive_policy())
    line = (
        b'{"jsonrpc":"2.0","id":"abc","method":"tools/call",'
        b'"params":{"name":"run_command","arguments":{"command":"git status"}}}\n'
    )

    action = processor.handle_client_line(line)
    response = _loads(action.to_client or b"{}")

    assert action.to_server is None
    assert response["error"]["code"] == APPROVAL_REQUIRED


def test_approval_grant_allows_matching_approval_required_call(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    arguments = {"command": "git status"}
    now = datetime.now(UTC)
    ledger.add_approval_grant(
        ApprovalGrant(
            agent_id="mcp-client",
            source="mcp_stdio",
            tool_name="run_command",
            arguments_hash=hash_tool_arguments(arguments),
            approved_by="security",
            reason="local repository status",
            created_at=now,
            expires_at=now + timedelta(minutes=5),
        )
    )
    processor = MCPMessageProcessor(policy=_permissive_policy(), ledger=ledger)
    line = (
        b'{"jsonrpc":"2.0","id":17,"method":"tools/call",'
        b'"params":{"name":"run_command","arguments":{"command":"git status"}}}\n'
    )

    action = processor.handle_client_line(line)
    events = ledger.list_events()

    assert action.to_server == line
    assert action.to_client is None
    assert [(event.decision, event.rule_id) for event in events] == [
        (Decision.ALLOW, f"approval.grant.{ledger.list_approval_grants(True)[0].grant_id}")
    ]
    assert ledger.list_approval_grants() == []


def test_approval_grant_does_not_override_deny(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    arguments = {"path": ".env"}
    now = datetime.now(UTC)
    ledger.add_approval_grant(
        ApprovalGrant(
            agent_id="mcp-client",
            source="mcp_stdio",
            tool_name="read_file",
            arguments_hash=hash_tool_arguments(arguments),
            approved_by="security",
            reason="should not bypass deny",
            created_at=now,
            expires_at=now + timedelta(minutes=5),
        )
    )
    processor = MCPMessageProcessor(policy=_permissive_policy(), ledger=ledger)
    line = (
        b'{"jsonrpc":"2.0","id":18,"method":"tools/call",'
        b'"params":{"name":"read_file","arguments":{"path":".env"}}}\n'
    )

    action = processor.handle_client_line(line)
    response = _loads(action.to_client or b"{}")

    assert action.to_server is None
    assert response["error"]["code"] == POLICY_DENIED
    assert response["error"]["data"]["rule_id"] == "path.sensitive"
    assert ledger.list_approval_grants()[0].used_count == 0


def test_allowed_call_is_correlated_and_response_is_redacted(tmp_path: Path) -> None:
    synthetic_token = b"sk-" + b"abcdefghijklmnopqrstuvwxyz"
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.upsert_tool_inventory(
        [
            ToolInventoryItem(
                source="mcp_stdio",
                name="read_file",
                capabilities=(Capability.FILESYSTEM_READ,),
            )
        ]
    )
    processor = MCPMessageProcessor(policy=_permissive_policy(), ledger=ledger)
    call_line = (
        b'{"jsonrpc":"2.0","id":3,"method":"tools/call",'
        b'"params":{"name":"read_file","arguments":{"path":"README.md"}}}\n'
    )

    call_action = processor.handle_client_line(call_line)
    response_action = processor.handle_server_line(
        b'{"jsonrpc":"2.0","id":3,"result":{"content":[{"type":"text",'
        b'"text":"OPENAI_API_KEY=' + synthetic_token + b'"}]}}\n'
    )
    response = _loads(response_action.to_client or b"{}")
    events = ledger.list_events()

    assert call_action.to_server == call_line
    assert synthetic_token.decode() not in json.dumps(response)
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
                discovered_at=datetime.now(UTC) - timedelta(seconds=30),
            )
        ]
    )
    processor = MCPMessageProcessor(
        policy=_permissive_policy(),
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
                discovered_at=datetime.now(UTC) - timedelta(seconds=30),
            )
        ]
    )
    processor = MCPMessageProcessor(
        policy=_permissive_policy(), ledger=ledger, inventory_ttl_seconds=1
    )
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
                discovered_at=datetime.now(UTC) - timedelta(days=365),
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
    processor = MCPMessageProcessor(policy=_permissive_policy())
    line = (
        b'{"jsonrpc":"2.0","id":13,"method":"tools/call",'
        b'"params":{"name":"run_command","arguments":{"command":"pwd"}}}\n'
    )

    action = processor.handle_client_line(line)
    response = _loads(action.to_client or b"{}")

    assert action.to_server is None
    assert response["error"]["code"] == APPROVAL_REQUIRED


def test_malformed_client_message_fails_closed() -> None:
    processor = MCPMessageProcessor(policy=_permissive_policy())

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
    synthetic_token = "sk-" + "integrationtestabcdefghijklmnopqrstuvwxyz"
    policy_path = tmp_path / "policy.yaml"
    ledger_path = tmp_path / "audit.sqlite"
    fake_server = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"
    policy_path.write_text(
        (
            # Explicit: the loader default is now deny, so a policy that relies on
            # allow-by-default must say so.
            "default_action: allow\n"
            "denied_capabilities:\n"
            "  - credential_access\n"
            "require_approval_capabilities:\n"
            "  - shell_execution\n"
            "  - production_mutation"
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
                        "arguments": {"text": "OPENAI_API_KEY=" + synthetic_token},
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

    process = subprocess.run(
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
            "2.0",
            "--",
            sys.executable,
            str(fake_server),
        ],
        input=payload,
        capture_output=True,
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
        responses_by_id[2]["result"]["content"][0]["text"] == "OPENAI_API_KEY=[REDACTED:openai_key]"
    )
    assert responses_by_id[3]["error"]["code"] == POLICY_DENIED
    assert responses_by_id[3]["error"]["data"]["rule_id"] == "capability.denied"
    assert {tool.name for tool in ledger.list_tool_inventory()} >= {"echo", "read_secret"}
    events_by_call: dict[str, list[Decision]] = {}
    for event in ledger.list_events():
        events_by_call.setdefault(event.call_id, []).append(event.decision)
    # Causal order is defined within a call. Independent requests may interleave.
    assert events_by_call["2"] == [Decision.ALLOW, Decision.REDACT]
    assert events_by_call["3"] == [Decision.DENY]


@pytest.mark.parametrize("_iteration", range(3))
def test_mcp_proxy_drains_high_volume_server_output(
    tmp_path: Path,
    _iteration: int,
) -> None:
    ledger_path = tmp_path / "audit.sqlite"
    fake_server = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"
    burst_count = 600
    payload = (
        json.dumps({"jsonrpc": "2.0", "id": 20, "method": "tools/list", "params": {}})
        + "\n"
        + json.dumps(
            {
                "jsonrpc": "2.0",
                "id": 21,
                "method": "tools/call",
                "params": {"name": "burst", "arguments": {}},
            }
        )
        + "\n"
    ).encode("utf-8")

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "agentguard.cli",
            "mcp-proxy",
            "--policy",
            str(_ALLOW_POLICY_PATH),
            "--ledger",
            str(ledger_path),
            "--shutdown-timeout-seconds",
            "2.0",
            "--",
            sys.executable,
            str(fake_server),
            "--burst-count",
            str(burst_count),
            "--burst-bytes",
            "512",
        ],
        input=payload,
        capture_output=True,
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
    assert len(responses) == burst_count + 2
    assert len(progress_messages) == burst_count
    assert progress_messages[0]["params"]["index"] == 0
    assert progress_messages[-1]["params"]["index"] == burst_count - 1
    assert final_response["id"] == 21
    assert final_response["result"]["content"][0]["text"] == f"burst:{burst_count}"
    assert [(event.tool_name, event.decision) for event in ledger.list_events()] == [
        ("burst", Decision.ALLOW)
    ]


def test_wait_or_stop_server_allows_natural_exit_after_output_eof(
    tmp_path: Path,
) -> None:
    proxy = MCPStdioProxy(
        [sys.executable, "server.py"],
        _permissive_policy(),
        AuditLedger(tmp_path / "audit.sqlite"),
        shutdown_timeout_seconds=0.25,
    )
    drain_state = _OutputDrainState()
    drain_state.completed.set()

    class NaturallyExitingProcess:
        def __init__(self) -> None:
            self.returncode: int | None = None
            self.wait_timeouts: list[float | None] = []

        def poll(self) -> int | None:
            return self.returncode

        def wait(self, timeout: float | None = None) -> int:
            self.wait_timeouts.append(timeout)
            self.returncode = 0
            return 0

    process = NaturallyExitingProcess()

    assert proxy._wait_or_stop_server(process, drain_state) is False
    assert process.returncode == 0
    assert process.wait_timeouts == [0.25]


def test_mcp_proxy_terminates_server_that_ignores_stdin_eof(tmp_path: Path) -> None:
    ledger_path = tmp_path / "audit.sqlite"
    fake_server = Path(__file__).parent / "fixtures" / "fake_mcp_server.py"

    process = subprocess.run(
        [
            sys.executable,
            "-m",
            "agentguard.cli",
            "mcp-proxy",
            "--policy",
            str(_ALLOW_POLICY_PATH),
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
        capture_output=True,
        timeout=5,
        check=False,
    )

    assert process.returncode != 0
    assert process.stdout == b""


def test_duplicate_outstanding_request_id_is_rejected() -> None:
    processor = MCPMessageProcessor(policy=_permissive_policy())
    first = processor.handle_client_line(
        b'{"jsonrpc":"2.0","id":41,"method":"tools/list","params":{}}\n'
    )
    duplicate = processor.handle_client_line(
        b'{"jsonrpc":"2.0","id":41,"method":"resources/list","params":{}}\n'
    )

    assert first.to_server is not None
    assert duplicate.to_server is None
    assert _loads(duplicate.to_client or b"{}")["error"]["code"] == -32600


def test_passthrough_request_id_cannot_collide_with_tool_call(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.upsert_tool_inventory(
        [
            ToolInventoryItem(
                source="mcp_stdio",
                name="read_file",
                capabilities=(Capability.FILESYSTEM_READ,),
            )
        ]
    )
    processor = MCPMessageProcessor(policy=_permissive_policy(), ledger=ledger)
    passthrough = processor.handle_client_line(
        b'{"jsonrpc":"2.0","id":"same","method":"resources/list","params":{}}\n'
    )
    collision = processor.handle_client_line(
        b'{"jsonrpc":"2.0","id":"same","method":"tools/call",'
        b'"params":{"name":"read_file","arguments":{"path":"README.md"}}}\n'
    )

    assert passthrough.to_server is not None
    assert collision.to_server is None
    assert _loads(collision.to_client or b"{}")["error"]["code"] == -32600


def test_server_initiated_request_does_not_consume_client_request_correlation(
    tmp_path: Path,
) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.upsert_tool_inventory(
        [
            ToolInventoryItem(
                source="mcp_stdio",
                name="read_file",
                capabilities=(Capability.FILESYSTEM_READ,),
            )
        ]
    )
    processor = MCPMessageProcessor(policy=_permissive_policy(), ledger=ledger)
    call = processor.handle_client_line(
        b'{"jsonrpc":"2.0","id":52,"method":"tools/call",'
        b'"params":{"name":"read_file","arguments":{"path":"README.md"}}}\n'
    )
    server_request = processor.handle_server_line(
        b'{"jsonrpc":"2.0","id":52,"method":"sampling/createMessage","params":{}}\n'
    )
    response = processor.handle_server_line(
        b'{"jsonrpc":"2.0","id":52,"result":{"content":"ok"}}\n'
    )

    assert call.to_server is not None
    assert _loads(server_request.to_client or b"{}")["method"] == "sampling/createMessage"
    assert _loads(response.to_client or b"{}")["result"]["content"] == "ok"
    assert ledger.list_events()[0].decision == Decision.ALLOW


def test_tools_list_changed_notification_invalidates_cached_inventory(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.upsert_tool_inventory(
        [
            ToolInventoryItem(
                source="mcp_stdio",
                name="read_file",
                capabilities=(Capability.FILESYSTEM_READ,),
            )
        ]
    )
    processor = MCPMessageProcessor(policy=_permissive_policy(), ledger=ledger)

    notification = processor.handle_server_line(
        b'{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}\n'
    )
    call = processor.handle_client_line(
        b'{"jsonrpc":"2.0","id":61,"method":"tools/call",'
        b'"params":{"name":"read_file","arguments":{"path":"README.md"}}}\n'
    )

    assert notification.to_client is not None
    assert ledger.get_tool_inventory("mcp_stdio", "read_file") is None
    assert _loads(call.to_client or b"{}")["error"]["data"]["rule_id"] == "inventory.unavailable"


def test_failed_tools_list_refresh_invalidates_cached_inventory(tmp_path: Path) -> None:
    ledger = AuditLedger(tmp_path / "audit.sqlite")
    ledger.upsert_tool_inventory(
        [
            ToolInventoryItem(
                source="mcp_stdio",
                name="read_file",
                capabilities=(Capability.FILESYSTEM_READ,),
            )
        ]
    )
    processor = MCPMessageProcessor(policy=_permissive_policy(), ledger=ledger)
    processor.handle_client_line(b'{"jsonrpc":"2.0","id":62,"method":"tools/list","params":{}}\n')
    processor.handle_server_line(
        b'{"jsonrpc":"2.0","id":62,"error":{"code":-32603,"message":"failed"}}\n'
    )

    assert ledger.get_tool_inventory("mcp_stdio", "read_file") is None
