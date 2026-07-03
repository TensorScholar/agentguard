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

### Security

- Redacts common secret-like values before persisting audit output.
- Avoids shell invocation for MCP subprocess execution.
- Fails closed for denied and approval-required tool calls.
- Keeps approval exceptions below hard-deny rules and requires capability scope.
- Adds responsible disclosure guidance.
