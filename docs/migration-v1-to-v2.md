# Migration from DecisionLock v0.1 to v0.2

The public repository currently contains a working MCP stdio proxy, tool inventory, local approval grants and a hash-chained audit ledger. Those capabilities must be preserved during migration; this package must not be force-pushed over the public history.

## Safe migration

```bash
git clone https://github.com/TensorScholar/decisionlock.git
cd decisionlock
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

## Phase 0 breaking changes

Two changes in the Phase 0 stabilization pass are breaking for existing callers.

**1. The v1 policy default is now `deny`.** `load_policy()` and the `Policy` dataclass previously
used `allow` when `default_action` was absent, which meant a minimal v1 policy authorized anything
it did not explicitly block. That default is now `deny`. Note that in the v1 model `allowed_tools` is
a narrowing check evaluated *first*, and `default_action` is only the fallback for tools that passed
it — so permitting a tool requires declaring both. To migrate:

```yaml
# before: implicitly allow-by-default
denied_tools:
  - delete_file

# after: explicit, and unmatched tools are denied by the allowlist
default_action: allow
allowed_tools:
  - read_file
  - write_file
denied_tools:
  - delete_file
```

Migrating to a v2 policy (`examples/scoped-refund/policy.yaml`) avoids this ambiguity entirely:
`PolicyDefaults.effect` is structurally `deny`.

**2. `authorize_execution` is renamed `preflight_execution`.** The function validates execution
authority but does not consume the decision nonce, so it never provided single-use enforcement; the
old name implied otherwise. The old name still resolves, but emits a `DeprecationWarning`. If your
integration relied on the old name to enforce single use, it was never doing so — the protected
execution lifecycle (`reserve_execution`) is the only path that claims execution authority.

## Audit database

Do not overwrite an existing audit database. Export the v0.1 head hash and report, retain the
database as evidence, and start the v0.2 schema in a new file. `SQLiteState` detects the v0.1
`audit_events` layout and raises `IncompatibleStateDatabaseError` before executing v0.2 DDL.
