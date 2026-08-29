# Limitations

- AgentGuard enforces only traffic routed through an AgentGuard adapter. `mcp-posture` detects direct
  routes in supplied configurations but cannot prove the absence of hidden, generated or network-level
  bypass paths.
- The v2 MCP processor requires a trusted, fresh schema resolver. Without one, `tools/call` fails
  closed with approval required.
- The HTTP module provides validation primitives, not a complete production Streamable HTTP proxy.
- Provenance and verified identity are only as trustworthy as the adapter that supplies them.
- Effect projection is adapter-supplied; ambiguous high-impact effects must never be projected as zero.
- SQLite replay, approval and issuance semantics are single-node. Multi-replica deployment requires
  a shared transactional repository.
- Canonical JSON supports the signed schema subset and rejects floats; this RC does not claim full
  RFC 8785 behavior for arbitrary JSON numbers.
- Signed audit checkpoints detect retained-prefix mismatch only when exported to independently
  controlled storage. Keeping the checkpoint beside the database adds little protection.
- Evidence signature verification authenticates the manifest key, not the business truth of the
  underlying event or the identity proofing process behind the signer.
- The mock credential broker is limited to contract testing and demos; no live production credential-provider integration is included.
- Interactive, identity-backed human approval UX is not included.
- No external penetration test, long-duration soak test or production pilot has been completed.
- AgentGuard applies owner-only file modes on POSIX systems. On Windows, sensitive files inherit
  NTFS ACLs from their containing directory; exact ACL hardening and verification require
  deployment-level ACL configuration. AgentGuard does not claim that POSIX `0600` semantics can be
  proven through `st_mode` on Windows.
- RC2 changes were locally exercised on Linux/Python 3.13. Cross-platform jobs are defined in CI but
  must run on the final Git commit before release promotion.
- Legacy Policy v1 retains compatibility-oriented semantics, including an allow default for ordinary
  known calls; production deployments should prefer Policy v2 and explicit allow rules.
- `mcp-proxy-v2` currently targets only the repository's `2025-03-26`-era stdio interoperability
  profile. It does not claim full MCP 2025-03-26 conformance and does not implement the MCP
  2026-07-28 task/session modernization.
- The protected v2 client method allowlist is limited to `initialize`, `notifications/initialized`,
  `ping`, `tools/list`, `tools/call`, and translated `notifications/cancelled`. JSON-RPC batches and
  unknown/custom client methods are unsupported and fail closed.
- Protected MCP schema binding relies on process-instance-bound `tools/list` observations,
  pagination completion, freshness, list-change invalidation, and a final observed digest check.
  A server can still change hidden semantics without exposing a corresponding protocol/schema change;
  AgentGuard does not claim cryptographic elimination of that residual TOCTOU assumption.
- Credential-bound protected MCP execution is intentionally unavailable in Phase 5B. The protected
  path does not use `MockCredentialBroker` as a substitute for a production credential injector.
- `mcp-proxy-v2` uses separate v0.2 state (default `.agentguard/action-integrity.sqlite`) and does not
  migrate or mutate the preserved v0.1 audit database.
- Legitimate provider tool output is not subjected to generic DLP/redaction by the protected MCP
  adapter. Secret minimization applies to AgentGuard-owned credentials, launch metadata, audit data,
  and execution evidence; generic provider-output DLP is outside this phase.
- Execution attestations authenticate AgentGuard's canonical execution evidence; they do not prove
  the truth of an external provider's unsigned evidence. `AGENTGUARD_SIGNED` and
  `PROVIDER_CORRELATED` evidence cannot promote an ambiguous execution to a confirmed external
  outcome. `PROVIDER_VERIFIED` reconciliation must be supplied only by a reconciler whose provider
  verification contract is independently trusted.
- Reconciliation is append-only and never redispatches. Generic MCP stdio has no provider-neutral
  reconciliation API, so provider-specific reconcilers remain separate adapters rather than being
  inferred from MCP transport behavior. The generic `reconcile-execution --evidence` CLI accepts
  only non-confirming/manual evidence and rejects file-supplied `PROVIDER_VERIFIED` claims; confirmed
  outcomes require a trusted provider-specific reconciler injected through the application port.
- Authority grants are AgentGuard-signed capabilities, not a replacement for workload identity
  proofing. The authority graph trusts the configured authority signing/verifying root.
- Phase 5D authority is backward-compatible by default. Deployments that require every protected
  action to carry a grant+lease must instantiate the service with `require_authority=True`; otherwise
  authority-less Phase 5A/5B callers remain valid. This mode does not itself authenticate the caller
  that supplies a `Principal`; workload identity proofing remains an external control.
- Capability leases are enforced transactionally by the single-node SQLite repository. A future
  multi-replica deployment requires an equivalent shared transactional lease-claim implementation.
- Capability scopes use exact protocol/server/tool/operation/resource matching in this phase. More
  expressive resource predicates must preserve monotonic attenuation and require separate review.
- `maximum_calls` is treated as a conservatively allocated authority budget: child grants and leases
  atomically reserve from their parent/grant budget. Revoked, expired, or unused allocations are not
  automatically reclaimed in Phase 5D, avoiding accidental authority multiplication at the cost of
  requiring a fresh grant when capacity was over-allocated.

- Phase 5D authority references are enforced at the normalized `ActionIntent` / application-service
  boundary. The protected Phase 5B MCP profile intentionally rejects unbound extension fields, so it
  does not yet accept client-supplied delegated-authority metadata; a future MCP adapter mapping must
  bind authority references explicitly rather than weakening the protected request-field allowlist.
