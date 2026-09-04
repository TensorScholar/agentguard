from __future__ import annotations

import json
import shutil
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, BinaryIO
from uuid import uuid4

from agentguard.application import AgentGuardService, ExecutionPersistenceError
from agentguard.domain import (
    Effect,
    ExecutionStatus,
    PolicyDocument,
    Principal,
    ProtectedExecutionResult,
    Resource,
    VerifiedExecution,
)
from agentguard.engine.canonical import digest
from agentguard.ports import AmbiguousExecutionError, DefiniteExecutionFailure

from .intent import intent_from_tools_call
from .jsonrpc import MCPProtocolError, encode_message, error_response, parse_message
from .stdio import _bounded_lines, _kill_process, _terminate_process, _write_locked

SUPPORTED_PROTOCOL_PROFILE = "2025-03-26"
PROTECTED_POLICY_DENIED = -32001
PROTECTED_APPROVAL_REQUIRED = -32002
PROTECTED_EXECUTION_ERROR = -32003
PROTECTED_OUTCOME_UNKNOWN = -32004
PROTECTED_PROFILE_UNSUPPORTED = -32005
PROTECTED_REQUEST_REJECTED = -32006
PROTECTED_SCHEMA_UNAVAILABLE = -32007

_ALLOWED_REQUEST_METHODS = frozenset({"initialize", "ping", "tools/list", "tools/call"})
_ALLOWED_NOTIFICATION_METHODS = frozenset({"notifications/initialized", "notifications/cancelled"})
_TOOL_LIST_CHANGED = "notifications/tools/list_changed"
_SECRET_FLAG_MARKERS = ("token", "secret", "password", "credential", "api-key", "apikey")


@dataclass(frozen=True)
class MCPServerBinding:
    server_id: str
    server_instance_id: str
    launch_fingerprint: str
    resolved_executable: str
    working_directory: str

    @classmethod
    def for_launch(
        cls,
        server_id: str,
        command: list[str],
        *,
        cwd: Path | None = None,
    ) -> MCPServerBinding:
        if not server_id:
            raise ValueError("server_id is required")
        if not command:
            raise ValueError("server command is required")
        working_directory = str((cwd or Path.cwd()).resolve())
        executable = shutil.which(command[0])
        if executable is None:
            candidate = Path(command[0]).expanduser()
            executable = str(candidate.resolve()) if candidate.exists() else command[0]
        safe_argv = _secret_minimized_argv(command)
        fingerprint = digest(
            {
                "argv": safe_argv,
                "resolved_executable": executable,
                "working_directory": working_directory,
            }
        )
        return cls(
            server_id=server_id,
            server_instance_id="mcpsrv_" + uuid4().hex,
            launch_fingerprint=fingerprint,
            resolved_executable=executable,
            working_directory=working_directory,
        )


@dataclass(frozen=True)
class BoundToolSchema:
    schema: dict[str, Any]
    schema_digest: str
    discovered_at: datetime
    server_id: str
    server_instance_id: str


class SessionToolSchemaCache:
    """Connection/process-instance-bound schema inventory for the protected old-profile path."""

    def __init__(self, binding: MCPServerBinding, *, ttl_seconds: float = 300.0) -> None:
        if ttl_seconds <= 0:
            raise ValueError("schema ttl must be greater than zero")
        self.binding = binding
        self.ttl_seconds = ttl_seconds
        self._schemas: dict[str, BoundToolSchema] = {}
        self._expected_cursor: str | None = None
        self._complete = False
        self._lock = threading.Lock()

    def invalidate(self) -> None:
        with self._lock:
            self._schemas.clear()
            self._expected_cursor = None
            self._complete = False

    def observe_tools_list_page(
        self,
        response: dict[str, Any],
        *,
        requested_cursor: str | None,
        observed_at: datetime | None = None,
    ) -> bool:
        now = observed_at or datetime.now(UTC)
        result = response.get("result")
        if not isinstance(result, dict):
            self.invalidate()
            return False
        tools = result.get("tools")
        if not isinstance(tools, list):
            self.invalidate()
            return False
        next_cursor = result.get("nextCursor")
        if next_cursor is not None and (not isinstance(next_cursor, str) or not next_cursor):
            self.invalidate()
            return False
        parsed: dict[str, BoundToolSchema] = {}
        for tool in tools:
            if not isinstance(tool, dict):
                self.invalidate()
                return False
            name = tool.get("name")
            input_schema = tool.get("inputSchema")
            if not isinstance(name, str) or not name or not isinstance(input_schema, dict):
                self.invalidate()
                return False
            schema: dict[str, Any] = {"inputSchema": input_schema}
            output_schema = tool.get("outputSchema")
            if output_schema is not None:
                if not isinstance(output_schema, dict):
                    self.invalidate()
                    return False
                schema["outputSchema"] = output_schema
            parsed[name] = BoundToolSchema(
                schema=schema,
                schema_digest=digest(schema),
                discovered_at=now,
                server_id=self.binding.server_id,
                server_instance_id=self.binding.server_instance_id,
            )

        with self._lock:
            if requested_cursor is None:
                self._schemas = {}
                self._expected_cursor = None
                self._complete = False
            elif requested_cursor != self._expected_cursor:
                self._schemas = {}
                self._expected_cursor = None
                self._complete = False
                return False
            for name, item in parsed.items():
                existing = self._schemas.get(name)
                if existing is not None and existing.schema_digest != item.schema_digest:
                    self._schemas = {}
                    self._expected_cursor = None
                    self._complete = False
                    return False
                self._schemas[name] = item
            self._expected_cursor = next_cursor
            self._complete = next_cursor is None
        return True

    @property
    def complete(self) -> bool:
        with self._lock:
            return self._complete

    def resolve(self, tool: str, *, now: datetime | None = None) -> BoundToolSchema | None:
        current = now or datetime.now(UTC)
        with self._lock:
            if not self._complete:
                return None
            item = self._schemas.get(tool)
        if item is None:
            return None
        if item.server_id != self.binding.server_id:
            return None
        if item.server_instance_id != self.binding.server_instance_id:
            return None
        if item.discovered_at.tzinfo is None or item.discovered_at.utcoffset() is None:
            return None
        if current - item.discovered_at > timedelta(seconds=self.ttl_seconds):
            return None
        if digest(item.schema) != item.schema_digest:
            return None
        return item


class MCPProtectedSession:
    def __init__(
        self,
        binding: MCPServerBinding,
        *,
        request_id_capacity: int = 4096,
        schema_ttl_seconds: float = 300.0,
    ) -> None:
        if request_id_capacity < 1:
            raise ValueError("request_id_capacity must be at least one")
        self.binding = binding
        self.request_id_capacity = request_id_capacity
        self.schemas = SessionToolSchemaCache(binding, ttl_seconds=schema_ttl_seconds)
        self._request_ids: dict[str, str] = {}
        self._tools_list_requests: dict[str, str | None] = {}
        self._initialize_request_key: str | None = None
        self._requested_profile: str | None = None
        self._negotiated_profile: str | None = None
        self._executions: dict[str, str] = {}
        self._cancelled: set[str] = set()
        self._lock = threading.Lock()

    @staticmethod
    def request_key(request_id: Any) -> str:
        if isinstance(request_id, bool) or not isinstance(request_id, (str, int)):
            raise ValueError("request id must be a string or integer")
        return json.dumps(request_id, ensure_ascii=False, separators=(",", ":"))

    def register_request_id(self, request_id: Any, forensic_digest: str) -> str | None:
        key = self.request_key(request_id)
        with self._lock:
            if key in self._request_ids:
                return "mcp.request_id_reused"
            if len(self._request_ids) >= self.request_id_capacity:
                return "mcp.request_id_registry_exhausted"
            self._request_ids[key] = forensic_digest
        return None

    def note_initialize_request(self, request_id: Any, profile: str) -> None:
        key = self.request_key(request_id)
        with self._lock:
            self._initialize_request_key = key
            self._requested_profile = profile
            self._negotiated_profile = None

    def observe_initialize_response(self, response: dict[str, Any]) -> None:
        try:
            key = self.request_key(response.get("id"))
        except ValueError:
            return
        with self._lock:
            if key != self._initialize_request_key:
                return
            result = response.get("result")
            negotiated = result.get("protocolVersion") if isinstance(result, dict) else None
            self._negotiated_profile = negotiated if isinstance(negotiated, str) else None

    @property
    def negotiated_profile(self) -> str | None:
        with self._lock:
            return self._negotiated_profile

    @property
    def protected_profile_supported(self) -> bool:
        with self._lock:
            return (
                self._requested_profile == SUPPORTED_PROTOCOL_PROFILE
                and self._negotiated_profile == SUPPORTED_PROTOCOL_PROFILE
            )

    def note_tools_list_request(self, request_id: Any, cursor: str | None) -> None:
        with self._lock:
            self._tools_list_requests[self.request_key(request_id)] = cursor

    def observe_tools_list_response(self, response: dict[str, Any]) -> bool | None:
        try:
            key = self.request_key(response.get("id"))
        except ValueError:
            return None
        with self._lock:
            if key not in self._tools_list_requests:
                return None
            cursor = self._tools_list_requests.pop(key)
        return self.schemas.observe_tools_list_page(response, requested_cursor=cursor)

    def bind_execution(self, client_request_key: str, execution_id: str) -> None:
        with self._lock:
            self._executions[client_request_key] = execution_id

    def execution_for_client_request(self, request_id: Any) -> str | None:
        try:
            key = self.request_key(request_id)
        except ValueError:
            return None
        with self._lock:
            return self._executions.get(key)

    def cancel(self, client_request_key: str) -> str | None:
        with self._lock:
            self._cancelled.add(client_request_key)
            return self._executions.get(client_request_key)

    def is_cancelled(self, client_request_key: str) -> bool:
        with self._lock:
            return client_request_key in self._cancelled


@dataclass
class _PendingResponse:
    event: threading.Event
    response: dict[str, Any] | None = None
    failure_code: str | None = None
    write_attempted: bool = False
    cancelled: bool = False


class MCPProtectedTransport:
    """Correlates protected execution IDs and never exposes their responses to generic relay."""

    def __init__(self, process: subprocess.Popen[bytes], *, write_lock: threading.Lock) -> None:
        if process.stdin is None:
            raise ValueError("downstream stdin is required")
        self.process = process
        self.stdin = process.stdin
        self.write_lock = write_lock
        self._pending: dict[str, _PendingResponse] = {}
        self._protected_ids: set[str] = set()
        self._lock = threading.Lock()

    def request(
        self,
        execution_id: str,
        payload: bytes,
        *,
        timeout_seconds: float,
        cancelled: Callable[[], bool],
    ) -> dict[str, Any]:
        if timeout_seconds <= 0:
            raise DefiniteExecutionFailure("mcp.execution_timeout_invalid")
        pending = _PendingResponse(event=threading.Event())
        with self._lock:
            if execution_id in self._protected_ids:
                raise DefiniteExecutionFailure("mcp.execution_id_reused")
            self._protected_ids.add(execution_id)
            self._pending[execution_id] = pending

        if cancelled():
            self._remove_pending(execution_id)
            raise DefiniteExecutionFailure("mcp.cancelled_before_dispatch")
        if self.process.poll() is not None:
            self._remove_pending(execution_id)
            raise DefiniteExecutionFailure("mcp.process_unavailable")

        try:
            with self.write_lock:
                if cancelled():
                    self._remove_pending(execution_id)
                    raise DefiniteExecutionFailure("mcp.cancelled_before_dispatch")
                if self.process.poll() is not None:
                    self._remove_pending(execution_id)
                    raise DefiniteExecutionFailure("mcp.process_unavailable")
                pending.write_attempted = True
                self.stdin.write(payload)
                self.stdin.flush()
        except DefiniteExecutionFailure:
            raise
        except (BrokenPipeError, OSError) as exc:
            self._remove_pending(execution_id)
            raise AmbiguousExecutionError("mcp.downstream_write_ambiguous") from exc

        deadline = time.monotonic() + timeout_seconds
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._remove_pending(execution_id)
                raise AmbiguousExecutionError("mcp.response_timeout")
            pending.event.wait(min(0.02, remaining))
            if cancelled() or pending.cancelled:
                self._remove_pending(execution_id)
                raise AmbiguousExecutionError("mcp.cancelled_after_dispatch")
            if pending.failure_code is not None:
                code = pending.failure_code
                self._remove_pending(execution_id)
                raise AmbiguousExecutionError(code)
            if pending.response is not None:
                response = pending.response
                self._remove_pending(execution_id)
                return response
            if self.process.poll() is not None:
                self._remove_pending(execution_id)
                raise AmbiguousExecutionError("mcp.process_exited_after_dispatch")

    def deliver_response(self, message: dict[str, Any]) -> bool:
        execution_id = message.get("id")
        if not isinstance(execution_id, str):
            return False
        with self._lock:
            if execution_id not in self._protected_ids:
                return False
            pending = self._pending.get(execution_id)
            if pending is not None:
                pending.response = message
                pending.event.set()
            return True

    def owns_execution_id(self, execution_id: Any) -> bool:
        if not isinstance(execution_id, str):
            return False
        with self._lock:
            return execution_id in self._protected_ids

    def cancel_execution(self, execution_id: str) -> None:
        with self._lock:
            pending = self._pending.get(execution_id)
            if pending is not None:
                pending.cancelled = True
                pending.event.set()

    def fail_all_pending(self, code: str) -> None:
        with self._lock:
            for pending in self._pending.values():
                pending.failure_code = code
                pending.event.set()

    def send_control(self, payload: bytes) -> bool:
        try:
            with self.write_lock:
                if self.process.poll() is not None:
                    return False
                self.stdin.write(payload)
                self.stdin.flush()
            return True
        except (BrokenPipeError, OSError):
            return False

    def _remove_pending(self, execution_id: str) -> None:
        with self._lock:
            self._pending.pop(execution_id, None)


class MCPProtectedExecutor:
    def __init__(
        self,
        *,
        session: MCPProtectedSession,
        transport: MCPProtectedTransport,
        client_request_key: str,
        timeout_seconds: float,
    ) -> None:
        self.session = session
        self.transport = transport
        self.client_request_key = client_request_key
        self.timeout_seconds = timeout_seconds
        self.response: dict[str, Any] | None = None

    def execute(self, verified_execution: VerifiedExecution) -> ProtectedExecutionResult:
        self._validate_binding(verified_execution)
        current_schema = self.session.schemas.resolve(verified_execution.intent.action.tool)
        if current_schema is None:
            raise DefiniteExecutionFailure("mcp.tool_schema_unavailable_at_dispatch")
        if current_schema.schema_digest != digest(verified_execution.intent.tool_schema):
            raise DefiniteExecutionFailure("mcp.tool_schema_changed_at_dispatch")

        self.session.bind_execution(self.client_request_key, verified_execution.execution_id)
        downstream = {
            "jsonrpc": "2.0",
            "id": verified_execution.execution_id,
            "method": "tools/call",
            "params": {
                "name": verified_execution.intent.action.tool,
                "arguments": verified_execution.intent.arguments,
            },
        }
        response = self.transport.request(
            verified_execution.execution_id,
            encode_message(downstream),
            timeout_seconds=self.timeout_seconds,
            cancelled=lambda: self.session.is_cancelled(self.client_request_key),
        )
        self.response = response
        response_digest = digest(response)
        if "error" in response:
            error = response.get("error")
            provider_status = error.get("code") if isinstance(error, dict) else None
            return ProtectedExecutionResult(
                status=ExecutionStatus.FAILURE,
                provider_status=provider_status if isinstance(provider_status, int) else None,
                result_digest=response_digest,
                error_code="mcp.jsonrpc_error",
            )
        result = response.get("result")
        if not isinstance(result, dict):
            raise AmbiguousExecutionError("mcp.malformed_correlated_response")
        if result.get("isError") is True:
            return ProtectedExecutionResult(
                status=ExecutionStatus.FAILURE,
                result_digest=response_digest,
                error_code="mcp.tool_result_error",
            )
        return ProtectedExecutionResult(
            status=ExecutionStatus.SUCCESS,
            result_digest=response_digest,
        )

    def _validate_binding(self, verified: VerifiedExecution) -> None:
        intent = verified.intent
        resource = intent.resource
        if intent.action.protocol != "mcp" or intent.action.operation != "call":
            raise DefiniteExecutionFailure("mcp.execution_binding_invalid")
        if intent.action.server != self.session.binding.server_id:
            raise DefiniteExecutionFailure("mcp.server_binding_mismatch")
        if resource is None or resource.type != "mcp_stdio_server":
            raise DefiniteExecutionFailure("mcp.resource_binding_missing")
        if resource.id != self.session.binding.server_id:
            raise DefiniteExecutionFailure("mcp.resource_server_mismatch")
        attributes = resource.attributes
        if attributes.get("server_instance_id") != self.session.binding.server_instance_id:
            raise DefiniteExecutionFailure("mcp.server_instance_mismatch")
        if attributes.get("launch_fingerprint") != self.session.binding.launch_fingerprint:
            raise DefiniteExecutionFailure("mcp.launch_fingerprint_mismatch")
        if attributes.get("protocol_profile") != SUPPORTED_PROTOCOL_PROFILE:
            raise DefiniteExecutionFailure("mcp.protocol_profile_binding_mismatch")
        if not self.session.protected_profile_supported:
            raise DefiniteExecutionFailure("mcp.protocol_profile_unsupported")


class MCPProtectedStdioProxy:
    """Explicit opt-in protected MCP stdio profile; legacy mcp-proxy remains unchanged."""

    def __init__(
        self,
        service: AgentGuardService,
        policy: PolicyDocument,
        principal: Principal,
        server_id: str,
        server_command: list[str],
        *,
        request_id_capacity: int = 4096,
        schema_ttl_seconds: float = 300.0,
        execution_timeout_seconds: float = 30.0,
        shutdown_timeout_seconds: float = 2.0,
        max_message_bytes: int = 1_000_000,
        cwd: Path | None = None,
    ) -> None:
        if not server_command:
            raise ValueError("server command is required")
        if execution_timeout_seconds <= 0:
            raise ValueError("execution timeout must be greater than zero")
        if shutdown_timeout_seconds < 0:
            raise ValueError("shutdown timeout cannot be negative")
        self.service = service
        self.policy = policy
        self.principal = principal
        self.server_command = list(server_command)
        self.max_message_bytes = max_message_bytes
        self.execution_timeout_seconds = execution_timeout_seconds
        self.shutdown_timeout_seconds = shutdown_timeout_seconds
        self.cwd = cwd
        self.binding = MCPServerBinding.for_launch(server_id, self.server_command, cwd=cwd)
        self.session = MCPProtectedSession(
            self.binding,
            request_id_capacity=request_id_capacity,
            schema_ttl_seconds=schema_ttl_seconds,
        )
        self._transport: MCPProtectedTransport | None = None
        self._has_run = False

    def run(self) -> int:
        if self._has_run:
            raise RuntimeError("protected MCP proxy instances are single-launch")
        self._has_run = True
        self.service.recover_incomplete_executions()
        process = subprocess.Popen(
            self.server_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            start_new_session=True,
            cwd=self.cwd,
        )
        assert process.stdin and process.stdout
        output_lock = threading.Lock()
        write_lock = threading.Lock()
        transport = MCPProtectedTransport(process, write_lock=write_lock)
        self._transport = transport
        client_done = threading.Event()
        server_done = threading.Event()
        workers: list[threading.Thread] = []

        server_thread = threading.Thread(
            target=self._relay_server,
            args=(process.stdout, sys.stdout.buffer, output_lock, transport, server_done),
            daemon=True,
        )
        client_thread = threading.Thread(
            target=self._relay_client,
            args=(
                sys.stdin.buffer,
                sys.stdout.buffer,
                output_lock,
                transport,
                workers,
                client_done,
            ),
            daemon=True,
        )
        server_thread.start()
        client_thread.start()

        while process.poll() is None:
            if server_done.is_set() or client_done.is_set():
                break
            time.sleep(0.01)

        deadline = time.monotonic() + self.shutdown_timeout_seconds
        for worker in workers:
            remaining = max(0.0, deadline - time.monotonic())
            worker.join(timeout=remaining)
        if process.poll() is None:
            _terminate_process(process)
            try:
                process.wait(timeout=self.shutdown_timeout_seconds)
            except subprocess.TimeoutExpired:
                _kill_process(process)
                process.wait()
        transport.fail_all_pending("mcp.process_closed")
        server_thread.join(timeout=max(1.0, self.shutdown_timeout_seconds * 2))
        return process.returncode if process.returncode is not None else 1

    def _relay_client(
        self,
        client: BinaryIO,
        output: BinaryIO,
        output_lock: threading.Lock,
        transport: MCPProtectedTransport,
        workers: list[threading.Thread],
        completed: threading.Event,
    ) -> None:
        try:
            for raw in _bounded_lines(client, self.max_message_bytes):
                if raw is None:
                    _write_locked(
                        output,
                        error_response(None, -32600, "MCP message exceeds configured limit"),
                        output_lock,
                    )
                    continue
                try:
                    decoded = json.loads(raw)
                except json.JSONDecodeError:
                    _write_locked(output, error_response(None, -32700, "parse error"), output_lock)
                    continue
                if isinstance(decoded, list):
                    _write_locked(
                        output,
                        error_response(
                            None,
                            PROTECTED_REQUEST_REJECTED,
                            "MCP batching is unsupported by the protected profile",
                        ),
                        output_lock,
                    )
                    continue
                try:
                    message = parse_message(raw, self.max_message_bytes)
                except MCPProtocolError as exc:
                    _write_locked(output, error_response(None, exc.code, str(exc)), output_lock)
                    continue
                request_id = message.get("id")
                if set(message) - {"jsonrpc", "id", "method", "params"}:
                    if request_id is not None:
                        _write_locked(
                            output,
                            error_response(
                                request_id,
                                PROTECTED_REQUEST_REJECTED,
                                "unsupported JSON-RPC extension fields",
                            ),
                            output_lock,
                        )
                    continue
                if request_id is not None:
                    try:
                        reason = self.session.register_request_id(request_id, digest(message))
                    except ValueError as exc:
                        _write_locked(output, error_response(None, -32600, str(exc)), output_lock)
                        continue
                    if reason is not None:
                        _write_locked(
                            output,
                            error_response(
                                request_id,
                                PROTECTED_REQUEST_REJECTED,
                                "AgentGuard rejected MCP request identifier",
                                {"reason_codes": [reason]},
                            ),
                            output_lock,
                        )
                        continue
                method = message.get("method")
                if method == "tools/call":
                    worker = threading.Thread(
                        target=self._execute_tools_call,
                        args=(message, output, output_lock, transport),
                        daemon=True,
                    )
                    workers.append(worker)
                    worker.start()
                    continue
                payload = self._supported_passthrough(message, transport)
                if payload is None:
                    if request_id is not None:
                        _write_locked(
                            output,
                            error_response(
                                request_id,
                                -32601,
                                "method unsupported by AgentGuard protected MCP profile",
                            ),
                            output_lock,
                        )
                    continue
                transport.send_control(payload)
        finally:
            completed.set()

    def _supported_passthrough(
        self,
        message: dict[str, Any],
        transport: MCPProtectedTransport,
    ) -> bytes | None:
        method = message.get("method")
        request_id = message.get("id")
        if request_id is None:
            if method not in _ALLOWED_NOTIFICATION_METHODS:
                return None
        elif method not in _ALLOWED_REQUEST_METHODS - {"tools/call"}:
            return None

        if method == "initialize":
            params = message.get("params")
            if not isinstance(params, dict):
                return None
            allowed = {"protocolVersion", "capabilities", "clientInfo"}
            if set(params) - allowed:
                return None
            profile = params.get("protocolVersion")
            capabilities = params.get("capabilities")
            client_info = params.get("clientInfo")
            if not isinstance(profile, str) or not isinstance(capabilities, dict):
                return None
            if not isinstance(client_info, dict):
                return None
            self.session.note_initialize_request(request_id, profile)
            return encode_message(
                {
                    "jsonrpc": "2.0",
                    "id": request_id,
                    "method": "initialize",
                    "params": {
                        "protocolVersion": profile,
                        "capabilities": capabilities,
                        "clientInfo": client_info,
                    },
                }
            )

        if method == "notifications/initialized":
            params = message.get("params", {})
            if params != {}:
                return None
            return encode_message({"jsonrpc": "2.0", "method": method, "params": {}})

        if method == "ping":
            params = message.get("params", {})
            if params != {}:
                return None
            return encode_message(
                {"jsonrpc": "2.0", "id": request_id, "method": "ping", "params": {}}
            )

        if method == "tools/list":
            params = message.get("params", {})
            if not isinstance(params, dict) or set(params) - {"cursor"}:
                return None
            cursor = params.get("cursor")
            if cursor is not None and (not isinstance(cursor, str) or not cursor):
                return None
            self.session.note_tools_list_request(request_id, cursor)
            out_params: dict[str, Any] = {}
            if cursor is not None:
                out_params["cursor"] = cursor
            return encode_message(
                {"jsonrpc": "2.0", "id": request_id, "method": "tools/list", "params": out_params}
            )

        if method == "notifications/cancelled":
            params = message.get("params")
            if not isinstance(params, dict) or set(params) - {"requestId", "reason"}:
                return None
            target = params.get("requestId")
            try:
                target_key = self.session.request_key(target)
            except ValueError:
                return None
            execution_id = self.session.cancel(target_key)
            if execution_id is None:
                return None
            transport.cancel_execution(execution_id)
            downstream_params: dict[str, Any] = {"requestId": execution_id}
            reason = params.get("reason")
            if isinstance(reason, str):
                downstream_params["reason"] = reason
            return encode_message(
                {"jsonrpc": "2.0", "method": "notifications/cancelled", "params": downstream_params}
            )
        return None

    def _execute_tools_call(
        self,
        message: dict[str, Any],
        output: BinaryIO,
        output_lock: threading.Lock,
        transport: MCPProtectedTransport,
    ) -> None:
        client_id = message.get("id")
        if set(message) - {"jsonrpc", "id", "method", "params"}:
            _write_locked(
                output,
                error_response(
                    client_id,
                    PROTECTED_REQUEST_REJECTED,
                    "unsupported JSON-RPC extension fields",
                ),
                output_lock,
            )
            return
        if client_id is None:
            _write_locked(
                output,
                error_response(None, -32600, "tools/call requires a request id"),
                output_lock,
            )
            return
        try:
            client_key = self.session.request_key(client_id)
        except ValueError as exc:
            _write_locked(output, error_response(None, -32600, str(exc)), output_lock)
            return
        if not self.session.protected_profile_supported:
            _write_locked(
                output,
                error_response(
                    client_id,
                    PROTECTED_PROFILE_UNSUPPORTED,
                    "protected tools/call requires negotiated MCP profile 2025-03-26",
                ),
                output_lock,
            )
            return
        params = message.get("params")
        if not isinstance(params, dict):
            _write_locked(
                output, error_response(client_id, -32602, "invalid tools/call params"), output_lock
            )
            return
        allowed_keys = {"name", "arguments", "_meta"}
        if set(params) - allowed_keys:
            _write_locked(
                output,
                error_response(client_id, -32602, "unsupported tools/call execution metadata"),
                output_lock,
            )
            return
        meta = params.get("_meta")
        if meta is not None:
            if not isinstance(meta, dict) or set(meta) - {"progressToken"}:
                _write_locked(
                    output,
                    error_response(client_id, -32602, "unsupported tools/call metadata"),
                    output_lock,
                )
                return
            # progressToken is intentionally omitted from the reconstructed downstream call.
        tool = params.get("name")
        arguments = params.get("arguments", {})
        if not isinstance(tool, str) or not tool or not isinstance(arguments, dict):
            _write_locked(
                output, error_response(client_id, -32602, "invalid tools/call"), output_lock
            )
            return
        resolved = self.session.schemas.resolve(tool)
        if resolved is None:
            _write_locked(
                output,
                error_response(
                    client_id,
                    PROTECTED_SCHEMA_UNAVAILABLE,
                    "trusted process-instance tool schema is unavailable",
                ),
                output_lock,
            )
            return
        resource = Resource(
            type="mcp_stdio_server",
            id=self.binding.server_id,
            attributes={
                "transport": "stdio",
                "server_instance_id": self.binding.server_instance_id,
                "launch_fingerprint": self.binding.launch_fingerprint,
                "protocol_profile": SUPPORTED_PROTOCOL_PROFILE,
            },
        )
        bound_message = {
            "jsonrpc": "2.0",
            "id": client_id,
            "method": "tools/call",
            "params": {"name": tool, "arguments": arguments},
        }
        try:
            intent = intent_from_tools_call(
                bound_message,
                principal=self.principal,
                server=self.binding.server_id,
                request_id="mcpreq_" + uuid4().hex,
                tool_schema=resolved.schema,
                resource=resource,
            )
            receipt = self.service.authorize(intent, self.policy)
        except Exception as exc:
            _write_locked(
                output,
                error_response(
                    client_id,
                    PROTECTED_EXECUTION_ERROR,
                    "authorization failed",
                    {"reason": type(exc).__name__},
                ),
                output_lock,
            )
            return
        if receipt.effect == Effect.DENY:
            _write_locked(
                output,
                error_response(
                    client_id,
                    PROTECTED_POLICY_DENIED,
                    "AgentGuard denied tool call",
                    {
                        "decision_id": receipt.decision_id,
                        "reason_codes": list(receipt.reason_codes),
                    },
                ),
                output_lock,
            )
            return
        if receipt.effect == Effect.REQUIRE_APPROVAL:
            _write_locked(
                output,
                error_response(
                    client_id,
                    PROTECTED_APPROVAL_REQUIRED,
                    "AgentGuard requires approval",
                    {
                        "decision_id": receipt.decision_id,
                        "reason_codes": list(receipt.reason_codes),
                    },
                ),
                output_lock,
            )
            return
        if receipt.credential_ceiling is not None:
            _write_locked(
                output,
                error_response(
                    client_id,
                    PROTECTED_APPROVAL_REQUIRED,
                    "credential-bound protected MCP execution is unavailable",
                    {"decision_id": receipt.decision_id},
                ),
                output_lock,
            )
            return
        executor = MCPProtectedExecutor(
            session=self.session,
            transport=transport,
            client_request_key=client_key,
            timeout_seconds=self.execution_timeout_seconds,
        )
        try:
            outcome = self.service.execute_protected(
                intent,
                receipt,
                None,
                executor,
                current_policy=self.policy,
            )
        except ExecutionPersistenceError:
            _write_locked(
                output,
                error_response(
                    client_id,
                    PROTECTED_OUTCOME_UNKNOWN,
                    "protected MCP outcome persistence is ambiguous",
                    {"retry_safe": False},
                ),
                output_lock,
            )
            return
        except Exception as exc:
            _write_locked(
                output,
                error_response(
                    client_id,
                    PROTECTED_EXECUTION_ERROR,
                    "protected MCP execution failed before a provider response",
                    {"reason": str(exc), "retry_safe": False},
                ),
                output_lock,
            )
            return

        if executor.response is not None:
            client_response = dict(executor.response)
            client_response["id"] = client_id
            _write_locked(output, encode_message(client_response), output_lock)
            return
        code = (
            PROTECTED_OUTCOME_UNKNOWN
            if outcome.status == ExecutionStatus.UNKNOWN
            else PROTECTED_EXECUTION_ERROR
        )
        _write_locked(
            output,
            error_response(
                client_id,
                code,
                "protected MCP execution did not produce a provider response",
                {
                    "execution_id": outcome.execution_id,
                    "status": outcome.status.value,
                    "error_code": outcome.error_code,
                    "retry_safe": False,
                },
            ),
            output_lock,
        )

    def _relay_server(
        self,
        server: BinaryIO,
        output: BinaryIO,
        output_lock: threading.Lock,
        transport: MCPProtectedTransport,
        completed: threading.Event,
    ) -> None:
        try:
            for raw in _bounded_lines(server, self.max_message_bytes):
                if raw is None:
                    transport.fail_all_pending("mcp.server_message_too_large")
                    _write_locked(
                        output,
                        error_response(None, -32000, "MCP server message exceeds configured limit"),
                        output_lock,
                    )
                    continue
                try:
                    message = parse_message(raw, self.max_message_bytes)
                except MCPProtocolError:
                    transport.fail_all_pending("mcp.malformed_server_response")
                    continue
                if transport.deliver_response(message):
                    continue
                if transport.owns_execution_id(message.get("id")):
                    continue
                self.session.observe_initialize_response(message)
                self.session.observe_tools_list_response(message)
                if message.get("method") == _TOOL_LIST_CHANGED:
                    self.session.schemas.invalidate()
                _write_locked(output, encode_message(message), output_lock)
        finally:
            transport.fail_all_pending("mcp.server_eof")
            completed.set()


def _secret_minimized_argv(command: list[str]) -> list[str]:
    safe: list[str] = []
    redact_next = False
    for arg in command:
        if redact_next:
            safe.append("<redacted>")
            redact_next = False
            continue
        lowered = arg.lower()
        if arg.startswith("-") and any(marker in lowered for marker in _SECRET_FLAG_MARKERS):
            if "=" in arg:
                flag = arg.split("=", 1)[0]
                safe.append(flag + "=<redacted>")
            else:
                safe.append(arg)
                redact_next = True
            continue
        safe.append(arg)
    return safe
