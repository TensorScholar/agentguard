from __future__ import annotations
from agentguard.adapters.protocols.mcp import MCPStdioProcessor
from agentguard.application import AgentGuardService

def test_mcp_denies_unknown_tool(policy, intent, signer, verifier, state):
    processor = MCPStdioProcessor(
        AgentGuardService(signer, verifier, state), policy, intent.principal, "customer-operations"
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
    )
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"unknown","arguments":{}}}\n'
    assert processor.process_client(raw).to_server == raw


def test_mcp_credential_bound_action_requires_executor(policy, intent, signer, verifier, state):
    processor = MCPStdioProcessor(
        AgentGuardService(signer, verifier, state), policy, intent.principal, "customer-operations"
    )
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"refund.create","arguments":{"order_id":"o"}}}\n'
    result = processor.process_client(raw)
    # The MCP adapter does not forge provenance or effect projections, so the bounded rule does not match.
    assert result.to_client is not None


def test_mcp_allows_policy_without_credential(intent, signer, verifier, state):
    from agentguard.domain import Effect, PolicyDocument
    from agentguard.domain.policy import ActionMatcher, PolicyDefaults, PolicyMetadata, PolicyRule
    policy = PolicyDocument(
        metadata=PolicyMetadata(id="allow-read", revision=1),
        defaults=PolicyDefaults(),
        rules=(
            PolicyRule(
                id="allow-read",
                priority=10,
                effect=Effect.ALLOW,
                action=ActionMatcher(tools=frozenset({"read_file"})),
            ),
        ),
    )
    processor = MCPStdioProcessor(
        AgentGuardService(signer, verifier, state), policy, intent.principal, "filesystem"
    )
    raw = b'{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"read_file","arguments":{"path":"README.md"}}}\n'
    assert processor.process_client(raw).to_server == raw
