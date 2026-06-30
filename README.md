# AgentGuard

AgentGuard is a local-first security gateway for AI agents, MCP servers, and tool-calling
workflows.

It answers three practical questions:

1. What tools can this agent access?
2. What dangerous actions should be blocked before execution?
3. What audit evidence exists after an agent run?

AgentGuard is intentionally not an eval platform, not an observability dashboard, and not an
LLM router. It is the runtime control layer between agents and tools.

## MVP Commands

```bash
python -m agentguard.cli scan --config examples/mcp_config.json --format markdown
python -m agentguard.cli check-call --policy examples/policy.yaml --tool read_file --arg path=.env
python -m agentguard.cli proxy --policy examples/policy.yaml --ledger .agentguard/audit.sqlite
python -m agentguard.cli report --ledger .agentguard/audit.sqlite --format markdown
```

`proxy` reads newline-delimited JSON tool-call envelopes from stdin and emits a policy decision for
each call. This is the first enforcement primitive; a true MCP transport adapter can wrap the same
policy engine later.

Example envelope:

```json
{"agent_id":"codex","tool_name":"read_file","arguments":{"path":".env"}}
```

## Product Boundary

AgentGuard owns:

- MCP/tool inventory scanning.
- Tool-risk classification.
- Policy enforcement before tool execution.
- Secret redaction in tool outputs.
- Local audit ledger and report generation.

AgentGuard does not own:

- Model evaluation and regression testing. Use AXIOM.
- Cost/routing benchmarks. Use cost-optimized-inference.
- Generic LLM observability dashboards.

## Commercial Wedge

The first sellable service is:

> "I will scan your AI agent and MCP setup for dangerous tool access, secret-exfiltration risk,
> and missing approval controls, then give you a working local policy guardrail."

The first product sale is a team policy/audit package for companies adopting coding agents or
internal MCP servers.

## Roadmap

See [docs/ROADMAP.md](docs/ROADMAP.md).
