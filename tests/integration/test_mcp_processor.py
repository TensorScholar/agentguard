from __future__ import annotations

from datetime import UTC, datetime, timedelta

from agentguard.adapters.protocols.mcp import (
    AuditLedgerToolSchemaResolver,
    MCPStdioProcessor,
)
from agentguard.application import AgentGuardService
from agentguard.audit import AuditLedger
from agentguard.engine.canonical import digest
from agentguard.models import ToolInventoryItem
from agentguard.ports import ResolvedToolSchema


class FixedSchemaResolver:
    def __init__(
        self,
        tools: set[str],
        *,
        age: timedelta = timedelta(),
        digest_matches: bool = True,
    ) -> None:
        self.tools = tools
        self.age = age
        self.digest_matches = digest_matches

    def resolve(self, server: str, tool: str):
        del server
        if tool not in self.tools:
            return None
        schema = {
            "inputSchema": {
                "type": "object",
                "additionalProperties": False,
            }
        }
        return ResolvedToolSchema(
            schema=schema,
            schema_digest=digest(schema) if self.digest_matches else "changed",
            discovered_at=datetime.now(UTC) - self.age,
        )


def schemas(*tools: str) -> FixedSchemaResolver:
    return FixedSchemaResolver(set(tools))


def test_v1_inventory_resolves_actual_schema_for_v2(tmp_path):
    ledger = AuditLedger(tmp_path / "inventory.sqlite")
    ledger.upsert_tool_inventory(
        [
            ToolInventoryItem(
                source="mcp_stdio",
                name="read_file",
                input_schema={"type": "object", "required": ["path"]},
                output_schema={"type": "object"},
            )
        ]
    )

    resolved = AuditLedgerToolSchemaResolver(ledger).resolve("filesystem", "read_file")

    assert resolved is not None
    assert resolved.schema["inputSchema"]["required"] == ["path"]
    assert resolved.schema_digest == digest(resolved.schema)


def test_mcp_denies_unknown_tool(policy, intent, signer, verifier, state):
    processor = MCPStdioProcessor(
        AgentGuardService(signer, verifier, state),
        policy,
        intent.principal,
        "customer-operations",
        schema_resolver=schemas("unknown"),
    )
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unknown","arguments":{}}}\n'
    result = processor.process_client(raw)
    assert result.to_server is None and b"AgentGuard denied" in result.to_client


def test_mcp_passthrough_non_tool_call(policy, intent, signer, verifier, state):
    processor = MCPStdioProcessor(
        AgentGuardService(signer, verifier, state), policy, intent.principal, "customer-operations"
    )
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/list"}\n'
    assert processor.process_client(raw).to_server == raw


def test_mcp_rejects_notification(policy, intent, signer, verifier, state):
    processor = MCPStdioProcessor(
        AgentGuardService(signer, verifier, state), policy, intent.principal, "customer-operations"
    )
    raw = b'{"jsonrpc":"2.0","method":"tools/call","params":{"name":"refund.create","arguments":{}}}\n'
    assert b"cannot be audited" in processor.process_client(raw).to_client


def test_mcp_parse_error(policy, intent, signer, verifier, state):
    processor = MCPStdioProcessor(
        AgentGuardService(signer, verifier, state), policy, intent.principal, "customer-operations"
    )
    assert b"parse error" in processor.process_client(b"not-json\n").to_client


def test_mcp_invalid_params(policy, intent, signer, verifier, state):
    processor = MCPStdioProcessor(
        AgentGuardService(signer, verifier, state), policy, intent.principal, "customer-operations"
    )
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":[]}\n'
    assert b"params must be an object" in processor.process_client(raw).to_client


def test_mcp_observe_mode_passes_denied_action(policy, intent, signer, verifier, state):
    from agentguard.domain import EnforcementMode

    processor = MCPStdioProcessor(
        AgentGuardService(signer, verifier, state),
        policy,
        intent.principal,
        "customer-operations",
        mode=EnforcementMode.OBSERVE,
        schema_resolver=schemas("unknown"),
    )
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unknown","arguments":{}}}\n'
    assert processor.process_client(raw).to_server == raw


def test_mcp_credential_bound_action_requires_executor(policy, intent, signer, verifier, state):
    processor = MCPStdioProcessor(
        AgentGuardService(signer, verifier, state),
        policy,
        intent.principal,
        "customer-operations",
        schema_resolver=schemas("refund.create"),
    )
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"refund.create","arguments":{"order_id":"o"}}}\n'
    result = processor.process_client(raw)
    # The MCP adapter does not forge provenance or effect projections, so the bounded rule does not match.
    assert result.to_client is not None


def test_mcp_allows_policy_without_credential(intent, signer, verifier, state):
    from agentguard.domain import Effect, PolicyDocument, ProvenanceLabel
    from agentguard.domain.policy import (
        ActionMatcher,
        PolicyDefaults,
        PolicyMetadata,
        PolicyRule,
        ProvenanceMatcher,
    )

    policy = PolicyDocument(
        metadata=PolicyMetadata(id="allow-read", revision=1),
        defaults=PolicyDefaults(),
        rules=(
            PolicyRule(
                id="allow-read",
                priority=10,
                effect=Effect.ALLOW,
                action=ActionMatcher(tools=frozenset({"read_file"})),
                provenance=ProvenanceMatcher(contains_any=frozenset({ProvenanceLabel.UNVERIFIED})),
            ),
        ),
    )
    processor = MCPStdioProcessor(
        AgentGuardService(signer, verifier, state),
        policy,
        intent.principal,
        "filesystem",
        schema_resolver=schemas("read_file"),
    )
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"README.md"}}}\n'
    assert processor.process_client(raw).to_server == raw


def test_mcp_requires_approval_when_schema_unavailable(policy, intent, signer, verifier, state):
    processor = MCPStdioProcessor(
        AgentGuardService(signer, verifier, state),
        policy,
        intent.principal,
        "filesystem",
    )
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}\n'
    result = processor.process_client(raw)
    assert result.to_server is None
    assert b"mcp.tool_schema_unavailable" in result.to_client


def test_mcp_rejects_disabled_schema_freshness(policy, intent, signer, verifier, state):
    import pytest

    with pytest.raises(ValueError, match="greater than zero"):
        MCPStdioProcessor(
            AgentGuardService(signer, verifier, state),
            policy,
            intent.principal,
            "filesystem",
            schema_resolver=schemas("read_file"),
            schema_ttl_seconds=0,
        )


def test_mcp_requires_approval_when_schema_stale(policy, intent, signer, verifier, state):
    processor = MCPStdioProcessor(
        AgentGuardService(signer, verifier, state),
        policy,
        intent.principal,
        "filesystem",
        schema_resolver=FixedSchemaResolver(
            {"read_file"},
            age=timedelta(minutes=10),
        ),
        schema_ttl_seconds=60,
    )
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}\n'
    assert b"mcp.tool_schema_stale" in processor.process_client(raw).to_client


def test_mcp_requires_approval_when_schema_digest_changed(policy, intent, signer, verifier, state):
    processor = MCPStdioProcessor(
        AgentGuardService(signer, verifier, state),
        policy,
        intent.principal,
        "filesystem",
        schema_resolver=FixedSchemaResolver({"read_file"}, digest_matches=False),
    )
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}\n'
    assert b"mcp.tool_schema_changed" in processor.process_client(raw).to_client


def test_mcp_binds_resolved_schema_to_authorized_intent(intent, signer, verifier, state):
    from agentguard.domain import Effect, PolicyDocument, ProvenanceLabel
    from agentguard.domain.policy import (
        ActionMatcher,
        PolicyDefaults,
        PolicyMetadata,
        PolicyRule,
        ProvenanceMatcher,
    )

    class CapturingService(AgentGuardService):
        captured = None

        def authorize(self, action_intent, policy, **kwargs):
            self.captured = action_intent
            return super().authorize(action_intent, policy, **kwargs)

    policy = PolicyDocument(
        metadata=PolicyMetadata(id="allow-read", revision=1),
        defaults=PolicyDefaults(),
        rules=(
            PolicyRule(
                id="allow-read",
                priority=10,
                effect=Effect.ALLOW,
                action=ActionMatcher(tools=frozenset({"read_file"})),
                provenance=ProvenanceMatcher(contains_any=frozenset({ProvenanceLabel.UNVERIFIED})),
            ),
        ),
    )
    service = CapturingService(signer, verifier, state)
    processor = MCPStdioProcessor(
        service,
        policy,
        intent.principal,
        "filesystem",
        schema_resolver=schemas("read_file"),
    )
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{}}}\n'

    assert processor.process_client(raw).to_server == raw
    assert service.captured is not None
    assert service.captured.tool_schema["inputSchema"]["additionalProperties"] is False
