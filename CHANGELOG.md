# Changelog

## 0.2.0rc2

### Security corrections

- Redact secret-bearing keys and token patterns again at the legacy audit persistence boundary.
- Create SQLite ledgers and private keys with owner-only permissions and secure-delete pragmas.
- Add explicit legacy-ledger sanitization and hash-chain rebuilding.
- Fail closed when MCP inventory is unavailable or stale instead of allowing vague tool names.
- Isolate MCP inventory and approval grants with a stable downstream server identity.
- Normalize encoded, Unicode, Windows-style and file-URI paths before sensitive-path matching.
- Normalize raw hosts, URLs, IDNA names, decimal/hex/octal/short IPv4, IPv4-mapped IPv6 and
  link-local metadata destinations.
- Fail closed on excessive nested URL encoding.
- Reject duplicate YAML keys, aliases, unknown policy fields and malformed exception scopes.
- Enforce approval budget ceilings and decision-bound approval validity windows.
- Prevent credential grants from outliving the decision receipt or exposing handles in brokered mode.
- Add symlink-aware, atomic file operations for keys, evidence, CLI output and SQLite state.
- Make both legacy and v2 MCP relays concurrent and bounded to avoid stdout backpressure deadlocks.
- Reject duplicate outstanding JSON-RPC IDs, preserve bidirectional request correlation and invalidate
  cached inventory on `tools/list_changed` or failed refresh.

### Market and operational controls

- Add `mcp-posture` to detect direct, ambiguous, invalid and parallel bypass routes.
- Add signed audit checkpoints for externally anchored truncation/replacement detection.
- Add optional Ed25519 evidence-manifest attestations and signature-required verification.
- Add an immutable generated schema for audit checkpoints and evidence attestations.
- Add non-root Docker packaging, cross-platform CI definitions and Dependabot configuration.
- Add two-pass security/product review, market-gap analysis and production deployment guidance.

## 0.2.0rc1

- Reframed AgentGuard as a provider-neutral action-integrity kernel.
- Added strict ActionIntent and Policy v2 schemas with default deny.
- Added provenance-aware policy, tenant binding and blast-radius budgets.
- Added Ed25519-signed decision receipts and execution-time digest binding.
- Added atomic replay prevention and credential ceiling verification.
- Added mock Loadout-style broker, correlated audit chain and evidence bundles.
- Preserved an MCP stdio enforcement path and added HTTP transport security checks.
