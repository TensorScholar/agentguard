# Limitations

This document states the current technical and operational boundary of the `0.2.0rc3` line. It is deliberately stricter than the implemented feature list.

## Enforcement and integration boundary

- AgentGuard enforces only traffic routed through an AgentGuard adapter. `mcp-posture` can detect bypasses in supplied configuration files but cannot prove the absence of hidden, generated, dynamically selected, or network-level routes.
- Verified identity, field provenance, effect projection, and declared causal ancestry are only as trustworthy and complete as the integration that supplies them. AgentGuard does not infer hidden dependencies from arbitrary application memory or external systems.
- The final executor/provider adapter is trusted to invoke the exact verified operation. Operating-system sandboxing, process isolation, filesystem MAC, and network egress enforcement are outside AgentGuard.

## MCP and HTTP boundary

- The protected stdio profile is a bounded `2025-03-26` interoperability target. The protected Streamable HTTP profile is a bounded `2026-07-28` target. AgentGuard does not claim full conformance with every MCP method, extension, task/session behavior, or future protocol revision.
- Unsupported/custom protected client methods and JSON-RPC batches fail closed rather than being forwarded generically.
- Schema binding protects protocol-observable tool identity/schema state; it cannot cryptographically prove that a provider did not change hidden semantics behind an unchanged schema.
- Non-loopback HTTP binding requires in-process TLS, a non-empty Bearer access token, and an explicit non-wildcard Host allowlist. Browser-reachable mode additionally requires an Origin allowlist. External TLS termination is not currently modeled as an equivalent trusted-proxy security boundary.
- Legitimate provider tool output is not subjected to generic DLP/redaction by the MCP adapter. Secret minimization applies to AgentGuard-owned credentials, launch metadata, durable state, audit, and execution evidence.

## Credential and provider boundary

- The included production credential source resolves an explicitly configured environment-held secret late in the execution path. It is not a general secret vault and does not mint provider-native/downscoped short-lived tokens.
- The preserved mock broker is for demos/contract testing and must not be represented as a production credential provider.
- Broader provider-specific credential integrations remain adapters that must independently prove audience/scope/tenant/lifetime and revocation semantics.
- External-effect bindings prove what AgentGuard intended to send and where; they do not prove the external provider's business truth.
- `AGENTGUARD_SIGNED` and `PROVIDER_CORRELATED` evidence cannot confirm an ambiguous external outcome. Only a trusted provider-specific reconciler may emit `PROVIDER_VERIFIED` evidence that confirms success or failure.
- Reconciliation never redispatches automatically. Without proven provider idempotency/replay safety, the default remains `RECONCILE_BEFORE_RETRY`. Automatic background workers exclude terminal resolutions (`CONFIRMED_SUCCEEDED`, `CONFIRMED_FAILED`, `CONFLICT`), while explicit operator reconciliation may recheck confirmed terminal outcomes to synthesize `CONFLICT` upon contradictory evidence.
- `REVERSIBLE` and `COMPENSATABLE` staging classifications do not implement generic provider-side undo or compensation.

## State and deployment boundary

- The supported SQLite service topology is **single-host, multi-process**. Processes must share a local filesystem database with ordinary SQLite locking/durability semantics.
- Automatic startup recovery is disabled because shared SQLite state alone cannot determine executor liveness; recovering stranded `DISPATCHING` executions is strictly an explicit, controlled operator action.
- Lease fencing prevents a stale reconciliation worker from committing authoritative resolution state after expiry/takeover, but it is not a distributed consensus protocol.
- Reconciliation worker fairness is strictly process-local to a continuously running worker daemon. Restarting the worker process or invoking `--once` resets candidate traversal to canonical storage order. No durable, cross-restart, or distributed scheduler fairness is claimed.
- Network filesystems and cross-host SQLite deployment are not covered by the correctness claim. Multi-host HA requires a shared transactional adapter that proves equivalent atomic reservation, lease, fencing, and durability properties.
- Owner-only file modes are applied on POSIX systems. On Windows, sensitive-file protection depends on deployment NTFS ACL configuration; POSIX `0600` semantics cannot be inferred from `st_mode`.
- Signed checkpoints detect retained-prefix mismatch only when exported to independently controlled storage. A checkpoint kept beside the database does not protect against complete local state replacement.

## Authorization-model boundary

- Canonical JSON for signed security objects supports the signed schema subset and intentionally rejects Python floating-point values. Provider-result hashing is a separate domain that normalizes and accepts finite JSON floating-point numbers while rejecting non-finite values (`NaN` and `Infinity`); this release candidate does not claim full RFC 8785 behavior or universal cross-runtime canonicalization.
- Authority grants are AgentGuard-signed capabilities, not workload identity proof. Caller/workload identity proofing remains an external control.
- Capability scope matching is intentionally exact for protocol/server/tool/operation/resource dimensions; future richer predicates must preserve monotonic attenuation.
- Allocated capability budgets are conservative. Revoked, expired, or unused allocations are not automatically reclaimed because silent reclamation can multiply authority.
- Typed releases are exact, short-lived execution exceptions. They do not relabel or erase historical provenance.
- Policy intelligence is advisory and deterministic; it never edits policy, issues authority, or replaces the enforcement result.

## Release and operational boundary

- Identity-backed interactive approval UX, HSM/KMS signer integration, SIEM storage, centralized policy distribution, and distributed multi-host coordination are not bundled services.
- Real-provider interoperability is adapter/profile specific; passing deterministic tests does not establish universal provider compatibility.
- No independent penetration test, long-duration soak test, or controlled production pilot has been completed for `0.2.0rc3`.
- A release candidate must not be described as production-certified merely because CI, Security, CodeQL, packaging, and reproducibility gates pass.
