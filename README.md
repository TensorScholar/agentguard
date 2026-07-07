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
python -m agentguard --version
python -m agentguard.cli doctor
python -m agentguard.cli init --pack coding-agent-local
python -m agentguard.cli demo --output .agentguard/demo --force
python -m agentguard.cli scan --config examples/mcp_config.json --format markdown
python -m agentguard.cli check-call \
  --policy .agentguard/policy.yaml \
  --tool read_file \
  --arg path=.env
python -m agentguard.cli proxy --policy .agentguard/policy.yaml --ledger .agentguard/audit.sqlite
python -m agentguard.cli approve-call \
  --ledger .agentguard/audit.sqlite \
  --tool run_command \
  --arg "command=git status" \
  --approved-by security \
  --reason "one local status check"
python -m agentguard.cli mcp-proxy \
  --policy .agentguard/policy.yaml \
  -- \
  --real-mcp-server --flag value
python -m agentguard.cli gate --config examples/mcp_config.json --fail-on-risk high
python -m agentguard.cli report --ledger .agentguard/audit.sqlite --format markdown
```

`python -m agentguard` is supported for installed-package and source-checkout usage. `doctor`
checks the local runtime basics: Python version, SQLite, git availability, package version, and
local output writability.

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
  --inventory-ttl-seconds 300 \
  --shutdown-timeout-seconds 2 \
  -- \
  npx -y @modelcontextprotocol/server-filesystem .
```

The command after `--` is passed as argv directly. AgentGuard never uses `shell=True`.

For compatibility verification against a real pinned MCP server, run the opt-in smoke:

```bash
AGENTGUARD_RUN_REAL_MCP_SMOKE=1 \
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=. \
python -m pytest -q -p no:cacheprovider tests/test_mcp_real_server_smoke.py
```

The smoke installs `@modelcontextprotocol/server-filesystem@2026.1.14` into pytest's temporary
directory, runs its Node entrypoint directly, captures `tools/list`, allows a read-only call, and
blocks a write-capable call through policy.

MCP stdio output is streamed line-by-line with a bounded message size. AgentGuard does not buffer
unbounded server output in memory; if the downstream client stops reading, backpressure propagates
through the pipe. Closed downstream pipes are handled as relay termination instead of uncaught
thread failures.

Discovered `tools/list` inventory is trusted for a bounded time window. By default, cached MCP tool
metadata expires after 300 seconds. If a known tool is called after its cached inventory is stale,
AgentGuard requires approval unless fallback policy already denies or requires approval. Set
`--inventory-ttl-seconds 0` only when a deployment intentionally wants non-expiring local inventory.

After `tools/list` inventory is captured, policy can deny or require approval by capability:

```yaml
denied_capabilities:
  - credential_access

require_approval_capabilities:
  - shell_execution
  - production_mutation
```

Approval-required calls fail closed unless an exact local approval grant exists. Grants are scoped
to agent, source, tool name, and a SHA-256 hash of the exact JSON arguments; they expire and are
one-use by default. They do not override denies:

```bash
python -m agentguard.cli approve-call \
  --ledger .agentguard/audit.sqlite \
  --source mcp_stdio \
  --agent-id mcp-client \
  --tool run_command \
  --arg "command=git status" \
  --approved-by security \
  --reason "one local repository status check" \
  --ttl-seconds 300
```

List active grants:

```bash
python -m agentguard.cli approvals --ledger .agentguard/audit.sqlite
```

Teams can also add temporary approval exceptions for known-safe workflows. Exceptions are scoped by
capability, can be narrowed by tool name pattern, expire on a specific date, and never override hard
denies for sensitive paths, credentials, blocked hosts, denied tools, or denied capabilities:

```yaml
approval_exceptions:
  - id: local-git-status
    reason: Allow local repository status checks during onboarding demo
    approved_by: security
    expires_at: 2099-01-01
    tool: run_*
    capabilities:
      - shell_execution
```

See [examples/policy_with_exception.yaml](examples/policy_with_exception.yaml).

Audit reports include both runtime decisions and discovered MCP tools:

```bash
python -m agentguard.cli report --ledger .agentguard/audit.sqlite --format markdown
```

CI gate example:

```bash
python -m agentguard.cli gate \
  --changed-from origin/main \
  --fail-on-risk high \
  --format findings-json \
  --output agentguard-findings.json \
  --summary-output agentguard-summary.md
```

`gate` exits non-zero when the highest discovered risk is at or above the selected threshold.
`--changed-from` limits scanning to MCP-shaped JSON configs changed since a git ref. `--output`
writes the markdown, dataclass JSON, or stable `findings-json` report to a file for CI artifacts.
`--summary-output` writes a compact markdown summary suitable for GitHub Actions step summaries.

## Local Demo

```bash
python -m agentguard.cli demo --output .agentguard/demo --force
python -m agentguard.cli gate \
  --config .agentguard/demo/dangerous_mcp_config.json \
  --fail-on-risk high
```

The demo generates a safe MCP config, a dangerous MCP config, a starter policy, sample JSONL tool
calls, and a README with the exact commands to run. See [docs/DEMO.md](docs/DEMO.md).

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

## Project Trust

- License: [MIT](LICENSE)
- Changelog: [CHANGELOG.md](CHANGELOG.md)
- Security policy: [SECURITY.md](SECURITY.md)
- Contributing guide: [CONTRIBUTING.md](CONTRIBUTING.md)
- Release checklist: [docs/RELEASE.md](docs/RELEASE.md)
