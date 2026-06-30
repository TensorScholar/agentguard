# AgentGuard Plan And Roadmap

## Strategic Position

AgentGuard is an agent-tool security product. It should stay narrow and prove value by blocking
real dangerous actions in developer and enterprise agent workflows.

The core thesis:

> Agents are receiving tool access faster than organizations are building authorization, audit, and
> data-loss controls around those tools.

The product must therefore prioritize deterministic enforcement over fuzzy model judgment.

## Target Buyer

Primary buyers:

- Security engineering.
- Platform engineering.
- AI platform teams.
- DevOps teams using coding agents, internal agents, CI agents, or MCP servers.

Early adopter wedge:

- Startups and engineering teams adopting Codex, Claude Code, Cursor, internal MCP servers, or
  GitHub automation agents.

## Phase 0: Working Local MVP

Goal: prove the product with a local CLI and repeatable demo.

Must ship:

- `agentguard scan`: discovers MCP configs and classifies exposed tool/server risk.
- `agentguard check-call`: evaluates a single tool call against policy.
- `agentguard proxy`: enforces policy on JSON tool-call envelopes and writes audit events.
- `agentguard report`: summarizes blocked, allowed, redacted, and approval-required events.
- `policy.yaml`: readable team policy file.
- SQLite audit ledger.
- Secret redaction for common token/private-key patterns.
- Unit tests for scanner, policy, secrets, and audit ledger.

Acceptance demo:

1. A fake agent tries to read `.env`.
2. AgentGuard blocks it.
3. A fake tool output contains an API key.
4. AgentGuard redacts it.
5. The report shows what was blocked and why.

## Phase 1: MCP-Native Enforcement

Goal: support real MCP clients and servers without changing policy semantics.

Deliverables:

- MCP stdio proxy adapter. (implemented)
- JSON-RPC request/response correlation. (implemented for `tools/call`)
- Tool-list pass-through and inventory capture from MCP `tools/list`. (implemented)
- Tool-call enforcement for `tools/call`. (implemented)
- Safe error responses for denied calls. (implemented)
- Audit record linking request, decision, and redaction events. (implemented)

Remaining hardening:

- Integration tests against at least one real MCP server.
- Optional human approval workflow instead of fail-closed `require_approval` responses.
- Backpressure and shutdown behavior tests under long-running server processes.
- Policy rules that can deny by discovered capability, not only per-call arguments.

Non-goals:

- No hosted dashboard yet.
- No ML-based prompt-injection classifier as a required control.

## Phase 2: Developer Workflow Adoption

Goal: make AgentGuard easy to use in repos and CI.

Deliverables:

- GitHub Action.
- `agentguard init` to generate starter policy.
- PR diff scanner for new or changed MCP/tool configs.
- Policy packs:
  - coding-agent-local;
  - ci-agent;
  - repo-maintainer;
  - production-operator.
- Markdown/PDF security report export.

## Phase 3: Team Product

Goal: become useful for security/platform teams.

Deliverables:

- Central policy repository support.
- Team audit export.
- SSO-ready hosted dashboard or self-hosted API.
- Slack/Jira notifications for blocked high-risk actions.
- Policy exceptions with expiry and approval metadata.
- Fleet reports across developer machines and CI runners.

## Phase 4: Enterprise Controls

Goal: become a serious enterprise control point.

Deliverables:

- OpenTelemetry export.
- SIEM export.
- Tamper-evident audit logs.
- Role-based approvals.
- Secrets-manager integrations.
- Kubernetes sidecar deployment.
- Compliance evidence packs for SOC2/ISO/internal AI governance.

## Engineering Principles

- Policy must be deterministic and testable.
- Default-deny for high-risk capabilities.
- Local-first before hosted.
- Audit everything, but never log raw secrets.
- Keep enforcement independent from any one agent vendor.
- Treat MCP as the first adapter, not the whole product.
- Do not duplicate AXIOM or cost-optimized-inference.

## Kill Criteria

Stop or pivot if:

- The product cannot intercept real agent tool calls in common workflows.
- Security buyers do not care about audit reports.
- Existing agent platforms ship equivalent policy enforcement broadly.
- The product becomes mostly an observability dashboard.
