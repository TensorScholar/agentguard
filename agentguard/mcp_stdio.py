from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import BinaryIO

from .audit import AuditLedger
from .models import AuditEvent, Decision, PolicyDecision, ToolCall, ToolInventoryItem
from .policy import Policy
from .risk import classify_tool_definition
from .secrets import redact_value


JSONRPC_VERSION = "2.0"
PARSE_ERROR = -32700
INVALID_REQUEST = -32600
POLICY_DENIED = -32001
APPROVAL_REQUIRED = -32002
SERVER_PROTOCOL_ERROR = -32003
DEFAULT_INVENTORY_TTL_SECONDS = 300.0


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
        inventory_wait_timeout_seconds: float = 0.25,
        inventory_ttl_seconds: float = DEFAULT_INVENTORY_TTL_SECONDS,
    ) -> None:
        if inventory_ttl_seconds < 0:
            raise ValueError("inventory_ttl_seconds cannot be negative")
        self.policy = policy
        self.ledger = ledger
        self.agent_id = agent_id
        self.source = source
        self.inventory_wait_timeout_seconds = inventory_wait_timeout_seconds
        self.inventory_ttl_seconds = inventory_ttl_seconds
        self._pending_calls: dict[str, ToolCall] = {}
        self._pending_tool_lists: set[str] = set()
        self._condition = threading.Condition()

    def handle_client_line(self, raw_line: bytes) -> ProxyAction:
        message = _decode_json_rpc(raw_line)
        if message is None:
            return ProxyAction(to_client=_jsonrpc_error(None, PARSE_ERROR, "Parse error"))
        if not isinstance(message, dict):
            return ProxyAction(to_client=_jsonrpc_error(None, INVALID_REQUEST, "Invalid request"))

        if message.get("method") == "tools/list" and message.get("id") is not None:
            with self._condition:
                self._pending_tool_lists.add(_request_key(message.get("id")))
            return ProxyAction(to_server=_ensure_newline(raw_line))

        if message.get("method") != "tools/call":
            return ProxyAction(to_server=_ensure_newline(raw_line))

        request_id = message.get("id")
        if request_id is None:
            return ProxyAction(
                to_client=_jsonrpc_error(
                    None,
                    INVALID_REQUEST,
                    (
                        "AgentGuard blocks tools/call notifications because they cannot be "
                        "audited safely"
                    ),
                )
            )

        params = message.get("params")
        if not isinstance(params, dict):
            return ProxyAction(
                to_client=_jsonrpc_error(
                    request_id,
                    INVALID_REQUEST,
                    "tools/call params must be an object",
                )
            )

        tool_name = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(tool_name, str) or not tool_name:
            return ProxyAction(
                to_client=_jsonrpc_error(
                    request_id,
                    INVALID_REQUEST,
                    "tools/call params.name is required",
                )
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
        self._wait_for_pending_tool_inventory()
        known_tool = self.ledger.get_tool_inventory(self.source, tool_name) if self.ledger else None
        decision = self._evaluate_call(call, known_tool)
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
                to_client=_jsonrpc_error(
                    None,
                    SERVER_PROTOCOL_ERROR,
                    "Invalid JSON-RPC from MCP server",
                )
            )
        if not isinstance(message, dict):
            return ProxyAction(to_client=_ensure_newline(raw_line))

        request_id = message.get("id")
        redacted = redact_value(message) if self.policy.redact_secret_outputs else message
        if request_id is None:
            return ProxyAction(to_client=_encode_json_rpc(redacted))

        call = self._pending_calls.pop(_request_key(request_id), None)
        if call is None and self._is_pending_tool_list(request_id):
            self._record_tool_inventory(message)
            self._notify_inventory_updated()
            return ProxyAction(to_client=_encode_json_rpc(redacted))
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

    def _record_tool_inventory(self, message: dict[str, object]) -> None:
        if self.ledger is None:
            return
        result = message.get("result")
        if not isinstance(result, dict):
            return
        tools = result.get("tools")
        if not isinstance(tools, list):
            return
        inventory: list[ToolInventoryItem] = []
        for tool in tools:
            if not isinstance(tool, dict) or not isinstance(tool.get("name"), str):
                continue
            input_schema = (
                tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
            )
            output_schema = (
                tool.get("outputSchema") if isinstance(tool.get("outputSchema"), dict) else {}
            )
            redacted_input = redact_value(input_schema)
            redacted_output = redact_value(output_schema)
            capabilities, risk, reasons = classify_tool_definition(tool)
            description = str(tool["description"]) if tool.get("description") is not None else None
            inventory.append(
                ToolInventoryItem(
                    source=self.source,
                    name=str(tool["name"]),
                    description=description,
                    input_schema=redacted_input if isinstance(redacted_input, dict) else {},
                    output_schema=redacted_output if isinstance(redacted_output, dict) else {},
                    capabilities=capabilities,
                    risk_level=risk,
                    reasons=reasons,
                )
            )
        self.ledger.replace_tool_inventory(self.source, inventory)

    def _evaluate_call(
        self,
        call: ToolCall,
        known_tool: ToolInventoryItem | None,
    ) -> PolicyDecision:
        if known_tool is None or not _inventory_expired(known_tool, self.inventory_ttl_seconds):
            known_capabilities = known_tool.capabilities if known_tool is not None else None
            return self.policy.evaluate(call, known_capabilities=known_capabilities)

        fallback_decision = self.policy.evaluate(call)
        if fallback_decision.decision != Decision.ALLOW:
            return fallback_decision

        return PolicyDecision(
            decision=Decision.REQUIRE_APPROVAL,
            reason=(
                "cached MCP tool inventory is stale; refresh tools/list before calling "
                f"'{call.tool_name}'"
            ),
            rule_id="inventory.stale",
            capabilities=known_tool.capabilities,
            redacted_arguments=redact_value(call.arguments),
        )

    def _is_pending_tool_list(self, request_id: object) -> bool:
        with self._condition:
            key = _request_key(request_id)
            if key not in self._pending_tool_lists:
                return False
            self._pending_tool_lists.remove(key)
            return True

    def _notify_inventory_updated(self) -> None:
        with self._condition:
            self._condition.notify_all()

    def _wait_for_pending_tool_inventory(self) -> None:
        if self.inventory_wait_timeout_seconds <= 0:
            return
        with self._condition:
            if self._pending_tool_lists:
                self._condition.wait(timeout=self.inventory_wait_timeout_seconds)


class MCPStdioProxy:
    def __init__(
        self,
        server_command: list[str],
        policy: Policy,
        ledger: AuditLedger,
        agent_id: str = "mcp-client",
        max_message_bytes: int = 1_000_000,
        shutdown_timeout_seconds: float = 2.0,
        inventory_ttl_seconds: float = DEFAULT_INVENTORY_TTL_SECONDS,
    ) -> None:
        if not server_command:
            raise ValueError("server command is required")
        if max_message_bytes < 1:
            raise ValueError("max_message_bytes must be greater than zero")
        if shutdown_timeout_seconds < 0:
            raise ValueError("shutdown_timeout_seconds cannot be negative")
        if inventory_ttl_seconds < 0:
            raise ValueError("inventory_ttl_seconds cannot be negative")
        self.server_command = server_command
        self.processor = MCPMessageProcessor(
            policy=policy,
            ledger=ledger,
            agent_id=agent_id,
            inventory_ttl_seconds=inventory_ttl_seconds,
        )
        self.max_message_bytes = max_message_bytes
        self.shutdown_timeout_seconds = shutdown_timeout_seconds

    def run(self) -> int:
        process = subprocess.Popen(  # noqa: S603 - explicit argv, never shell=True.
            self.server_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            start_new_session=True,
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
        self._wait_or_stop_server(process)
        server_thread.join(timeout=1.0)
        return process.returncode if process.returncode is not None else 1

    def _wait_or_stop_server(self, process: subprocess.Popen[bytes]) -> None:
        try:
            process.wait(timeout=self.shutdown_timeout_seconds)
            return
        except subprocess.TimeoutExpired:
            pass

        _terminate_process_group(process)
        try:
            process.wait(timeout=self.shutdown_timeout_seconds)
            return
        except subprocess.TimeoutExpired:
            pass

        _kill_process_group(process)
        process.wait()

    def _relay_client_to_server(
        self,
        client_input: BinaryIO,
        server_input: BinaryIO,
        client_output: BinaryIO,
    ) -> None:
        for raw_line in _iter_bounded_lines(client_input, self.max_message_bytes):
            if raw_line is None:
                if not _write_and_flush(
                    client_output,
                    _jsonrpc_error(None, INVALID_REQUEST, "MCP message is too large"),
                ):
                    return
                continue
            action = self.processor.handle_client_line(raw_line)
            if action.to_client is not None:
                if not _write_and_flush(client_output, action.to_client):
                    return
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
                if not _write_and_flush(
                    client_output,
                    _jsonrpc_error(None, SERVER_PROTOCOL_ERROR, "MCP server message is too large"),
                ):
                    return
                continue
            action = self.processor.handle_server_line(raw_line)
            if action.to_client is not None:
                if not _write_and_flush(client_output, action.to_client):
                    return


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


def _write_and_flush(stream: BinaryIO, payload: bytes) -> bool:
    try:
        stream.write(payload)
        stream.flush()
    except BrokenPipeError:
        return False
    return True


def _inventory_expired(tool: ToolInventoryItem, ttl_seconds: float) -> bool:
    if ttl_seconds <= 0:
        return False
    discovered_at = tool.discovered_at
    if discovered_at.tzinfo is None:
        discovered_at = discovered_at.replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc) - discovered_at > timedelta(seconds=ttl_seconds)


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


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except ProcessLookupError:
        return


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        return
