# Changelog

## Unreleased (Phase 0 stabilization)

Stabilization and honesty pass. No product features were added. Two changes are breaking and are
documented in [the v1 to v2 migration guide](docs/migration-v1-to-v2.md).

### Research honesty

- Add a `Research Status` section to `README.md` above the fold recording
  `RESEARCH_CLAIM: NOT_VALIDATED` and
  `AGENTGUARD_SPECIFIC_DIFFERENTIATION_THESIS: FALSIFIED_WITHIN_PROTOCOL`, the 6.45 slot-hold ratio
  favoring the no-guard baseline, the scope exclusions from
  `docs/research/FREEZE_V2_RESULT_ADJUDICATION.md` §6, and the unestablished product claims.
- State in the README that the core single-use-receipt / digest-revalidation pattern is not unique to
  this project and is specified in external work.

## 0.2.0rc3

### Runtime-integrity and provider boundary

- Add signed execution attestations, append-only reconciliation, delegated authority and consumable
  capability leases, field-level provenance and typed releases, staged high-impact execution,
  declared causal execution graphs, and deterministic least-authority/policy-counterfactual analysis.
- Add the modern protected MCP HTTP profile while preserving the bounded protected stdio profile.
- Freeze provider/external-effect contracts so ambiguous outcomes remain `UNKNOWN` until trusted
  provider reconciliation establishes stronger evidence; blind retry remains forbidden by default.
- Add provider-neutral production credential authority with late secret resolution, exact provider
  binding, durable revocation, and no provider secret in grants or AgentGuard durable state.
- Persist external-effect bindings before side-effecting dispatch and add provider-specific durable
  reconciliation with explicit `PROVIDER_VERIFIED` evidence semantics.
- Add single-host multi-process reconciliation leases with monotonic fencing tokens, crash-safe
  takeover, stale-worker rejection, explicit operator recovery, bounded worker polling, and operational probes.
- Require TLS, Bearer authentication, and an explicit Host allowlist before non-loopback HTTP binding;
  browser-reachable mode additionally requires an explicit Origin allowlist.

### Release hardening

- Move the release-candidate version to `0.2.0rc3` and enforce consistency across package metadata,
  runtime version metadata, citation metadata, and the changelog.
- Validate the fixed `cryptography==50.0.1` runtime profile and remove the temporary
  `PYSEC-2026-3552` dependency-audit ignore after upgrading beyond its fixed version.
- Add reproducible wheel/normalized-sdist checks, deterministic SBOM and release-manifest generation,
  package checksums, base-wheel and HTTP-extra clean-install smoke, and container smoke validation.
- Package the existing protected HTTP service CLI as the `agentguard-mcp-http` console entrypoint and
  exercise it from clean-installed wheels and the release-candidate container.
- Synchronize public architecture, threat, deployment, limitation, project-status, and release
  documentation with the validated Phase 6 boundary while retaining the non-production-certified
  promotion gate.

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
- Added a provider-neutral mock credential broker, correlated audit chain and evidence bundles.
- Preserved an MCP stdio enforcement path and added HTTP transport security checks.
