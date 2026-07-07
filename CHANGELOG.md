# Changelog

All notable changes to AgentGuard will be documented here.

The project follows a pragmatic pre-1.0 format until public releases begin.

## Unreleased

### Added

- Local MCP config scanner and risk classifier.
- Policy evaluator for sensitive paths, environment names, blocked network hosts, capabilities, and
  explicit tool allow/deny lists.
- JSONL policy proxy with SQLite audit ledger.
- MCP stdio proxy with `tools/list` inventory capture, `tools/call` enforcement, response
  redaction, bounded message size, and bounded subprocess shutdown.
- Built-in policy packs: `coding-agent-local` and `ci-agent`.
- `agentguard init`, `agentguard demo`, `agentguard gate`, `agentguard doctor`, and report export.
- GitHub Actions workflow for changed MCP config risk gating.
- Repeatable local demo with safe and dangerous MCP configurations.
- Package entrypoints for both `agentguard` and `python -m agentguard`.
- Stable `findings-json` scan output and compact CI summary output.
- Scoped approval exceptions with expiry, reason, and approver metadata.
- Opt-in real MCP compatibility smoke for pinned filesystem server enforcement.
- High-volume MCP stdio regression coverage for bounded streaming behavior.
- MCP tool inventory freshness controls with configurable TTL.
- Local expiring approval grants for exact approval-required tool calls.
- Audit ledger hash chaining with `verify-audit` integrity checks.

### Security

- Redacts common secret-like values before persisting audit output.
- Avoids shell invocation for MCP subprocess execution.
- Fails closed for denied and approval-required tool calls.
- Keeps approval exceptions below hard-deny rules and requires capability scope.
- Handles downstream MCP stdio pipe closure without uncaught relay-thread failures.
- Requires approval for stale known MCP tool inventory instead of trusting expired metadata.
- Ensures local approval grants do not override denied policy decisions.
- Detects local audit-event mutation or broken ledger continuity through chained hashes.
- Adds responsible disclosure guidance.
