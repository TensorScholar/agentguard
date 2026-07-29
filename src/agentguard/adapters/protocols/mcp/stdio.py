from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

from agentguard.application import AgentGuardService
from agentguard.domain import Effect, EnforcementMode, PolicyDocument, Principal
from agentguard.engine.canonical import digest
from agentguard.ports import ToolSchemaResolver

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
        service: AgentGuardService,
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
                    "AgentGuard requires approval because the current tool schema is not trusted",
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
                    "AgentGuard denied tool call",
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
                    "AgentGuard requires approval",
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
    def __init__(self, processor: MCPStdioProcessor, server_command: list[str]) -> None:
        if not server_command:
            raise ValueError("server command is required")
        self.processor = processor
        self.server_command = server_command

    def run(self) -> int:
        process = subprocess.Popen(
            self.server_command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,
            start_new_session=True,
        )
        assert process.stdin and process.stdout
        for line in sys.stdin.buffer:
            result = self.processor.process_client(line)
            if result.to_client:
                sys.stdout.buffer.write(result.to_client)
                sys.stdout.buffer.flush()
            if result.to_server:
                process.stdin.write(result.to_server)
                process.stdin.flush()
        process.stdin.close()
        for line in process.stdout:
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()
        return process.wait(timeout=10)
