from __future__ import annotations

import subprocess
import sys
from dataclasses import dataclass

from agentguard.application import AgentGuardService
from agentguard.domain import Effect, EnforcementMode, PolicyDocument, Principal

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
    ) -> None:
        self.service = service
        self.policy = policy
        self.principal = principal
        self.server = server
        self.mode = mode
        self.max_message_bytes = max_message_bytes

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
        try:
            intent = intent_from_tools_call(msg, principal=self.principal, server=self.server)
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
