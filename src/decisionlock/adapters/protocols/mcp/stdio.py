from __future__ import annotations

import os
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import BinaryIO, Iterator

from decisionlock.application import DecisionLockService
from decisionlock.domain import Effect, EnforcementMode, PolicyDocument, Principal
from decisionlock.engine.canonical import digest
from decisionlock.ports import ToolSchemaResolver

from .intent import intent_from_tools_call
from .jsonrpc import MCPProtocolError, error_response, parse_message

POLICY_DENIED = -32001
APPROVAL_REQUIRED = -32002


@dataclass(frozen=True)
class ProcessResult:
    to_server: bytes | None = None
    to_client: bytes | None = None


class MCPStdioProcessor:
    def __init__(
        self,
        service: DecisionLockService,
        policy: PolicyDocument,
        principal: Principal,
        server: str,
        mode: EnforcementMode = EnforcementMode.ENFORCE,
        max_message_bytes: int = 1_000_000,
        schema_resolver: ToolSchemaResolver | None = None,
        schema_ttl_seconds: float = 300.0,
    ) -> None:
        if schema_ttl_seconds <= 0:
            raise ValueError("schema_ttl_seconds must be greater than zero")
        self.service = service
        self.policy = policy
        self.principal = principal
        self.server = server
        self.mode = mode
        self.max_message_bytes = max_message_bytes
        self.schema_resolver = schema_resolver
        self.schema_ttl_seconds = schema_ttl_seconds

    @staticmethod
    def _newline(raw: bytes) -> bytes:
        return raw if raw.endswith(b"\n") else raw + b"\n"

    def process_client(self, raw: bytes) -> ProcessResult:
        try:
            msg = parse_message(raw, self.max_message_bytes)
        except MCPProtocolError as exc:
            return ProcessResult(to_client=error_response(None, exc.code, str(exc)))
        if msg.get("method") != "tools/call":
            return ProcessResult(to_server=self._newline(raw))
        if msg.get("id") is None:
            return ProcessResult(
                to_client=error_response(
                    None, -32600, "tools/call notifications cannot be audited safely"
                )
            )
        params = msg.get("params")
        if not isinstance(params, dict):
            return ProcessResult(
                to_client=error_response(
                    msg.get("id"),
                    -32602,
                    "tools/call params must be an object",
                )
            )
        tool = params.get("name")
        if not isinstance(tool, str) or not tool:
            return ProcessResult(
                to_client=error_response(
                    msg.get("id"),
                    -32602,
                    "tools/call params.name is required",
                )
            )
        if not isinstance(params.get("arguments", {}), dict):
            return ProcessResult(
                to_client=error_response(
                    msg.get("id"),
                    -32602,
                    "tools/call arguments must be an object",
                )
            )
        schema, reason = self._resolve_tool_schema(tool)
        if reason is not None:
            return ProcessResult(
                to_client=error_response(
                    msg.get("id"),
                    APPROVAL_REQUIRED,
                    "DecisionLock requires approval because the current tool schema is not trusted",
                    {"reason_codes": [reason]},
                )
            )
        try:
            intent = intent_from_tools_call(
                msg,
                principal=self.principal,
                server=self.server,
                tool_schema=schema,
            )
        except (TypeError, ValueError) as exc:
            return ProcessResult(to_client=error_response(msg.get("id"), -32602, str(exc)))
        receipt = self.service.authorize(intent, self.policy, mode=self.mode)
        if self.mode == EnforcementMode.OBSERVE:
            return ProcessResult(to_server=self._newline(raw))
        if receipt.effect == Effect.DENY:
            return ProcessResult(
                to_client=error_response(
                    msg.get("id"),
                    POLICY_DENIED,
                    "DecisionLock denied tool call",
                    {
                        "decision_id": receipt.decision_id,
                        "reason_codes": list(receipt.reason_codes),
                    },
                )
            )
        if receipt.effect == Effect.REQUIRE_APPROVAL:
            return ProcessResult(
                to_client=error_response(
                    msg.get("id"),
                    APPROVAL_REQUIRED,
                    "DecisionLock requires approval",
                    {
                        "decision_id": receipt.decision_id,
                        "reason_codes": list(receipt.reason_codes),
                    },
                )
            )
        if receipt.credential_ceiling is not None:
            return ProcessResult(
                to_client=error_response(
                    msg.get("id"),
                    APPROVAL_REQUIRED,
                    "Credential-bound execution requires a broker/executor adapter",
                    {"decision_id": receipt.decision_id},
                )
            )
        return ProcessResult(to_server=self._newline(raw))

    def _resolve_tool_schema(
        self,
        tool: str,
    ) -> tuple[dict[str, object], str | None]:
        if self.schema_resolver is None:
            return {}, "mcp.tool_schema_unavailable"
        resolved = self.schema_resolver.resolve(self.server, tool)
        if resolved is None or not resolved.schema:
            return {}, "mcp.tool_schema_unavailable"
        if resolved.discovered_at.tzinfo is None or resolved.discovered_at.utcoffset() is None:
            return {}, "mcp.tool_schema_stale"
        if datetime.now(UTC) - resolved.discovered_at > timedelta(seconds=self.schema_ttl_seconds):
            return {}, "mcp.tool_schema_stale"
        if digest(resolved.schema) != resolved.schema_digest:
            return {}, "mcp.tool_schema_changed"
        return resolved.schema, None


class MCPStdioProxy:
    def __init__(
        self,
        processor: MCPStdioProcessor,
        server_command: list[str],
        *,
        shutdown_timeout_seconds: float = 2.0,
    ) -> None:
        if not server_command:
            raise ValueError("server command is required")
        if shutdown_timeout_seconds < 0:
            raise ValueError("shutdown_timeout_seconds cannot be negative")
        self.processor = processor
        self.server_command = server_command
        self.shutdown_timeout_seconds = shutdown_timeout_seconds

    def run(self) -> int:
        process = subprocess.Popen(
            self.server_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            start_new_session=True,
        )
        assert process.stdin and process.stdout
        output_lock = threading.Lock()
        client_done = threading.Event()
        server_done = threading.Event()

        client_thread = threading.Thread(
            target=self._relay_client,
            args=(sys.stdin.buffer, process.stdin, sys.stdout.buffer, output_lock, client_done),
            daemon=True,
        )
        server_thread = threading.Thread(
            target=self._relay_server,
            args=(process.stdout, sys.stdout.buffer, output_lock, server_done),
            daemon=True,
        )
        server_thread.start()
        client_thread.start()

        deadline: float | None = None
        while process.poll() is None:
            if server_done.is_set():
                _terminate_process(process)
                deadline = time.monotonic() + self.shutdown_timeout_seconds
                break
            if client_done.is_set():
                deadline = time.monotonic() + self.shutdown_timeout_seconds
                break
            time.sleep(0.01)

        if deadline is not None:
            while process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.01)
        forced = False
        if process.poll() is None:
            forced = True
            _terminate_process(process)
            try:
                process.wait(timeout=self.shutdown_timeout_seconds)
            except subprocess.TimeoutExpired:
                _kill_process(process)
                process.wait()

        server_thread.join(timeout=max(1.0, self.shutdown_timeout_seconds * 2))
        if forced or not server_done.is_set():
            return 1
        return process.returncode if process.returncode is not None else 1

    def _relay_client(
        self,
        client: BinaryIO,
        server: BinaryIO,
        output: BinaryIO,
        output_lock: threading.Lock,
        completed: threading.Event,
    ) -> None:
        try:
            for line in _bounded_lines(client, self.processor.max_message_bytes):
                if line is None:
                    _write_locked(
                        output,
                        error_response(None, -32600, "MCP message exceeds configured limit"),
                        output_lock,
                    )
                    continue
                result = self.processor.process_client(line)
                if result.to_client is not None:
                    _write_locked(output, result.to_client, output_lock)
                if result.to_server is not None:
                    try:
                        server.write(result.to_server)
                        server.flush()
                    except BrokenPipeError:
                        return
        finally:
            try:
                server.close()
            except BrokenPipeError:
                pass
            completed.set()

    def _relay_server(
        self,
        server: BinaryIO,
        output: BinaryIO,
        output_lock: threading.Lock,
        completed: threading.Event,
    ) -> None:
        try:
            for line in _bounded_lines(server, self.processor.max_message_bytes):
                if line is None:
                    _write_locked(
                        output,
                        error_response(None, -32000, "MCP server message exceeds configured limit"),
                        output_lock,
                    )
                    continue
                _write_locked(output, line, output_lock)
        finally:
            completed.set()


def _bounded_lines(stream: BinaryIO, maximum: int) -> Iterator[bytes | None]:
    while True:
        line = stream.readline(maximum + 1)
        if line == b"":
            return
        if len(line) > maximum:
            if not line.endswith(b"\n"):
                while True:
                    remainder = stream.readline(8192)
                    if remainder == b"" or remainder.endswith(b"\n"):
                        break
            yield None
            continue
        yield line


def _write_locked(output: BinaryIO, payload: bytes, lock: threading.Lock) -> None:
    with lock:
        output.write(payload)
        output.flush()


def _terminate_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(process.pid, signal.SIGTERM)
        else:
            process.terminate()
    except ProcessLookupError:
        pass


def _kill_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        if hasattr(os, "killpg"):
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass
