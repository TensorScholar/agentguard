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
python -m agentguard.cli init --pack coding-agent-local
python -m agentguard.cli scan --config examples/mcp_config.json --format markdown
python -m agentguard.cli check-call \
  --policy .agentguard/policy.yaml \
  --tool read_file \
  --arg path=.env
python -m agentguard.cli proxy --policy .agentguard/policy.yaml --ledger .agentguard/audit.sqlite
python -m agentguard.cli mcp-proxy \
  --policy .agentguard/policy.yaml \
  -- \
  --real-mcp-server --flag value
python -m agentguard.cli report --ledger .agentguard/audit.sqlite --format markdown
```

`init` creates a starter policy from a built-in policy pack and refuses to overwrite an existing
policy unless `--force` is provided. Current packs:

- `coding-agent-local`: allow normal repo work, block credential access, gate
  shell/cloud/database/production actions.
- `ci-agent`: block credential/cloud/production access, gate file mutation, shell, and database
  actions.

`proxy` reads newline-delimited JSON tool-call envelopes from stdin and emits a policy decision for
each call. `mcp-proxy` is the Phase 1 production-shaped path: it launches a real MCP stdio server,
forwards JSON-RPC messages, captures `tools/list` inventory, intercepts `tools/call`, applies
policy before forwarding, redacts secret-like server output, and records audit events.
It also uses bounded shutdown handling so a server that ignores stdin close cannot leave the proxy
hung indefinitely.

Example envelope:

```json
{"agent_id":"codex","tool_name":"read_file","arguments":{"path":".env"}}
```

MCP stdio proxy example:

```bash
python -m agentguard.cli mcp-proxy \
  --policy .agentguard/policy.yaml \
  --ledger .agentguard/audit.sqlite \
  --shutdown-timeout-seconds 2 \
  -- \
  npx -y @modelcontextprotocol/server-filesystem .
```

The command after `--` is passed as argv directly. AgentGuard never uses `shell=True`.

After `tools/list` inventory is captured, policy can deny or require approval by capability:

```yaml
denied_capabilities:
  - credential_access

require_approval_capabilities:
  - shell_execution
  - production_mutation
```

Audit reports include both runtime decisions and discovered MCP tools:

```bash
python -m agentguard.cli report --ledger .agentguard/audit.sqlite --format markdown
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
