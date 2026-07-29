# Migration from AgentGuard v0.1 to v0.2

The public repository currently contains a working MCP stdio proxy, tool inventory, local approval grants and a hash-chained audit ledger. Those capabilities must be preserved during migration; this package must not be force-pushed over the public history.

## Safe migration

```bash
git clone https://github.com/TensorScholar/agentguard.git
cd agentguard
git fetch origin
test "$(git rev-parse origin/main)" = "5b76b0ef8694db0181ac47cc52d0662333b6ebc6"
git switch --create rebuild/action-integrity-v2 origin/main
```

Do not import the independent release bundle as repository history and do not copy the complete
v0.1 tree into a `legacy/` directory. Git history already preserves that source. The rebuilt branch
moves materially required v0.1 modules into the `src/` package and keeps their regression tests.

## Compatibility

`compatibility.policy_v1.migrate_policy_v1` converts explicit v1 tool allow/deny lists into a default-deny Policy v2 document. Sensitive-path, host and capability policies require manual review because a mechanical migration could incorrectly broaden authority.

The installed CLI preserves the v0.1 `doctor`, `scan`, `gate`, `check-call`, `proxy`,
`approve-call`, `approvals`, `mcp-proxy`, `report`, and `verify-audit` commands. The v0.2 `init`
and `demo` workflows are the defaults; the v0.2 demo includes the v0.1 compatibility fixtures
under `v1-compat/`.

## Audit database

Do not overwrite an existing audit database. Export the v0.1 head hash and report, retain the
database as evidence, and start the v0.2 schema in a new file. `SQLiteState` detects the v0.1
`audit_events` layout and raises `IncompatibleStateDatabaseError` before executing v0.2 DDL.
