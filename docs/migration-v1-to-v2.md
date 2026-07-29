# Migration from AgentGuard v0.1 to v0.2

The public repository currently contains a working MCP stdio proxy, tool inventory, local approval grants and a hash-chained audit ledger. Those capabilities must be preserved during migration; this package must not be force-pushed over the public history.

## Safe migration

```bash
git clone https://github.com/TensorScholar/agentguard.git
cd agentguard
git checkout -b rebuild/action-integrity-v2
mkdir -p legacy/v0.1
# Move the v0.1 Python package, tests and docs to legacy/v0.1 in a reviewed commit,
# then apply the v0.2 source tree from this package.
```

Recommended commit sequence:

1. `chore: checkpoint AgentGuard v0.1 baseline`
2. `refactor: preserve v0.1 implementation under legacy`
3. `feat: introduce action-integrity v2 kernel`
4. `test: add adversarial and integration coverage`
5. `docs: add Loadout integration RFC and migration guide`

## Compatibility

`compatibility.policy_v1.migrate_policy_v1` converts explicit v1 tool allow/deny lists into a default-deny Policy v2 document. Sensitive-path, host and capability policies require manual review because a mechanical migration could incorrectly broaden authority.

## Audit database

Do not overwrite an existing audit database. Export the v0.1 head hash and report, retain the database as evidence, and start the v0.2 schema in a new file until a reviewed migration is added.
