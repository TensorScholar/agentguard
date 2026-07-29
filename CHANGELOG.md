# Changelog

## 0.2.0rc1

- Reframed AgentGuard as a provider-neutral action-integrity kernel.
- Added strict ActionIntent and Policy v2 schemas with default deny.
- Added provenance-aware policy, tenant binding and blast-radius budgets.
- Added Ed25519-signed decision receipts and execution-time digest binding.
- Added atomic replay prevention and credential ceiling verification.
- Added mock Loadout-style broker, correlated audit chain and evidence bundles.
- Preserved an MCP stdio enforcement path and added HTTP transport security checks.
- Hardened receipt verification, complete intent binding, authenticated grants, atomic issuance,
  approval consumption, current-policy verification, and delegation ceilings.
- Bound v2 MCP calls to fresh discovered schemas and fixed cross-platform stdio drain ordering.
- Made evidence verification reject unlisted files and security timestamps reject naive values.
