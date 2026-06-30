from __future__ import annotations

import json
import subprocess
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from typing import BinaryIO

from .audit import AuditLedger
from .models import AuditEvent, Decision, PolicyDecision, ToolCall
from .policy import Policy
from .secrets import redact_value


JSONRPC_VERSION = "2.0"
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
POLICY_DENIED = -32001
APPROVAL_REQUIRED = -32002
SERVER_PROTOCOL_ERROR = -32003


@dataclass(frozen=True)
class ProxyAction:
    to_server: bytes | None = None
    to_client: bytes | None = None


class MCPMessageProcessor:
    """Policy-aware MCP JSON-RPC message processor."""

    def __init__(
        self,
        policy: Policy,
        ledger: AuditLedger | None = None,
        agent_id: str = "mcp-client",
        source: str = "mcp_stdio",
    ) -> None:
        self.policy = policy
        self.ledger = ledger
        self.agent_id = agent_id
        self.source = source
        self._pending_calls: dict[str, ToolCall] = {}

    def handle_client_line(self, raw_line: bytes) -> ProxyAction:
        message = _decode_json_rpc(raw_line)
        if message is None:
            return ProxyAction(to_client=_jsonrpc_error(None, PARSE_ERROR, "Parse error"))
        if not isinstance(message, dict):
            return ProxyAction(to_client=_jsonrpc_error(None, INVALID_REQUEST, "Invalid request"))

        if message.get("method") != "tools/call":
            return ProxyAction(to_server=_ensure_newline(raw_line))

        request_id = message.get("id")
        if request_id is None:
            return ProxyAction(
                to_client=_jsonrpc_error(
                    None,
                    INVALID_REQUEST,
                    "AgentGuard blocks tools/call notifications because they cannot be audited safely",
                )
            )

        params = message.get("params")
        if not isinstance(params, dict):
            return ProxyAction(
                to_client=_jsonrpc_error(request_id, INVALID_REQUEST, "tools/call params must be an object")
            )

        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(tool_name, str) or not tool_name:
            return ProxyAction(
                to_client=_jsonrpc_error(request_id, INVALID_REQUEST, "tools/call params.name is required")
            )
        if not isinstance(arguments, dict):
            return ProxyAction(
                to_client=_jsonrpc_error(
                    request_id, INVALID_REQUEST, "tools/call params.arguments must be an object"
                )
            )

        call = ToolCall(
            tool_name=tool_name,
            arguments=arguments,
            agent_id=self.agent_id,
            source=self.source,
            call_id=_request_key(request_id),
        )
        decision = self.policy.evaluate(call)
        self._record(AuditEvent.from_decision(call, decision))

        if decision.decision == Decision.DENY:
            return ProxyAction(
                to_client=_jsonrpc_error(
                    request_id,
                    POLICY_DENIED,
                    "AgentGuard denied tool call",
                    _decision_error_data(decision),
                )
            )
        if decision.decision == Decision.REQUIRE_APPROVAL:
            return ProxyAction(
                to_client=_jsonrpc_error(
                    request_id,
                    APPROVAL_REQUIRED,
                    "AgentGuard requires approval before tool call",
                    _decision_error_data(decision),
                )
            )

        self._pending_calls[_request_key(request_id)] = call
        return ProxyAction(to_server=_ensure_newline(raw_line))

    def handle_server_line(self, raw_line: bytes) -> ProxyAction:
        message = _decode_json_rpc(raw_line)
        if message is None:
            return ProxyAction(
                to_client=_jsonrpc_error(None, SERVER_PROTOCOL_ERROR, "Invalid JSON-RPC from MCP server")
            )
        if not isinstance(message, dict):
            return ProxyAction(to_client=_ensure_newline(raw_line))

        request_id = message.get("id")
        redacted = redact_value(message) if self.policy.redact_secret_outputs else message
        if request_id is None:
            return ProxyAction(to_client=_encode_json_rpc(redacted))

        call = self._pending_calls.pop(_request_key(request_id), None)
        if call is not None and redacted != message:
            self._record(
                AuditEvent.from_decision(
                    call,
                    PolicyDecision(
                        decision=Decision.REDACT,
                        reason="redacted secret-like content from MCP server response",
                        rule_id="response.secret_redaction",
                        redacted_arguments={"response_redacted": True},
                    ),
                )
            )
        return ProxyAction(to_client=_encode_json_rpc(redacted))

    def _record(self, event: AuditEvent) -> None:
        if self.ledger is not None:
            self.ledger.record(event)


class MCPStdioProxy:
    def __init__(
        self,
        server_command: list[str],
        policy: Policy,
        ledger: AuditLedger,
        agent_id: str = "mcp-client",
        max_message_bytes: int = 1_000_000,
    ) -> None:
        if not server_command:
            raise ValueError("server command is required")
        self.server_command = server_command
        self.processor = MCPMessageProcessor(policy=policy, ledger=ledger, agent_id=agent_id)
        self.max_message_bytes = max_message_bytes

    def run(self) -> int:
        process = subprocess.Popen(  # noqa: S603 - explicit argv, never shell=True.
            self.server_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
        )
        if process.stdin is None or process.stdout is None:
            raise RuntimeError("failed to open MCP server stdio pipes")

        client_thread = threading.Thread(
            target=self._relay_client_to_server,
            args=(sys.stdin.buffer, process.stdin, sys.stdout.buffer),
            daemon=True,
        )
        server_thread = threading.Thread(
            target=self._relay_server_to_client,
            args=(process.stdout, sys.stdout.buffer),
            daemon=True,
        )
        server_thread.start()
        client_thread.start()
        client_thread.join()
        process.wait()
        server_thread.join(timeout=1.0)
        return process.returncode if process.returncode is not None else 1

    def _relay_client_to_server(
        self,
        client_input: BinaryIO,
        server_input: BinaryIO,
        client_output: BinaryIO,
    ) -> None:
        for raw_line in _iter_bounded_lines(client_input, self.max_message_bytes):
            if raw_line is None:
                client_output.write(_jsonrpc_error(None, INVALID_REQUEST, "MCP message is too large"))
                client_output.flush()
                continue
            action = self.processor.handle_client_line(raw_line)
            if action.to_client is not None:
                client_output.write(action.to_client)
                client_output.flush()
            if action.to_server is not None:
                try:
                    server_input.write(action.to_server)
                    server_input.flush()
                except BrokenPipeError:
                    return
        try:
            server_input.close()
        except BrokenPipeError:
            return

    def _relay_server_to_client(self, server_output: BinaryIO, client_output: BinaryIO) -> None:
        for raw_line in _iter_bounded_lines(server_output, self.max_message_bytes):
            if raw_line is None:
                client_output.write(
                    _jsonrpc_error(None, SERVER_PROTOCOL_ERROR, "MCP server message is too large")
                )
                client_output.flush()
                continue
            action = self.processor.handle_server_line(raw_line)
            if action.to_client is not None:
                client_output.write(action.to_client)
                client_output.flush()


def _iter_bounded_lines(stream: BinaryIO, max_bytes: int) -> Iterator[bytes | None]:
    while True:
        line = stream.readline(max_bytes + 1)
        if line == b"":
            return
        if len(line) > max_bytes:
            if not line.endswith(b"\n"):
                _drain_line(stream)
            yield None
            continue
        yield line


def _drain_line(stream: BinaryIO) -> None:
    while True:
        chunk = stream.readline(8192)
        if chunk == b"" or chunk.endswith(b"\n"):
            return


def _decode_json_rpc(raw_line: bytes) -> object | None:
    try:
        return json.loads(raw_line.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None


def _jsonrpc_error(
    request_id: object,
    code: int,
    message: str,
    data: dict[str, object] | None = None,
) -> bytes:
    payload: dict[str, object] = {
        "jsonrpc": JSONRPC_VERSION,
        "id": request_id,
        "error": {"code": code, "message": message},
    }
    if data is not None:
        error = payload["error"]
        assert isinstance(error, dict)
        error["data"] = redact_value(data)
    return _encode_json_rpc(payload)


def _decision_error_data(decision: PolicyDecision) -> dict[str, object]:
    return {
        "rule_id": decision.rule_id,
        "reason": decision.reason,
        "capabilities": [capability.value for capability in decision.capabilities],
    }


def _encode_json_rpc(payload: object) -> bytes:
    return (json.dumps(redact_value(payload), separators=(",", ":"), sort_keys=True) + "\n").encode(
        "utf-8"
    )


def _ensure_newline(raw_line: bytes) -> bytes:
    return raw_line if raw_line.endswith(b"\n") else raw_line + b"\n"


def _request_key(request_id: object) -> str:
    return json.dumps(request_id, sort_keys=True, separators=(",", ":"))
