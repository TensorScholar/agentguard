# Limitations

This document states the current technical and operational boundary of the `0.2.0rc3` line. It is deliberately stricter than the implemented feature list.

**Scope of this release line.** AgentGuard leads with four mechanisms: decision-bound credential
ceilings with late secret resolution; execution-time digest revalidation with single-use claim; durable
external-effect binding with reconcile-before-retry; and a hash-chained ledger with offline-verifiable
evidence. See the [product thesis](product-boundary.md) and
[Credential Contract](credential-contract.md). Everything else the codebase implements — causal
execution graphs, field provenance and typed releases, policy counterfactuals, delegated authority
trees, approval receipts, checkpoint signing — is advanced surface, not the product, and no claim depends
on it.

## Non-goals for this release line

Boundaries, not roadmap items. Listed first because they are the fastest way to disqualify this project
if it is not a fit.

- **Multi-host, HA, or distributed consensus.** Single-host multi-process over local SQLite only.
- **Issuing or verifying identity.** AgentGuard binds identity that a trusted integration supplies. It
  does not mint, prove, or verify workload identity.
- **Generic policy-gateway competition.** No policy authoring, simulation, or content filtering.
- **Secret storage, rotation, or token minting.** One environment variable, read at dispatch, never
  persisted.
- **Process isolation or network egress control.**
- **Production certification.** No independent penetration test, soak test, or production pilot has
  completed.

## Enforcement and integration boundary

- AgentGuard enforces only traffic routed through an AgentGuard adapter. `mcp-posture` can detect bypasses in supplied configuration files but cannot prove the absence of hidden, generated, dynamically selected, or network-level routes. **If the agent can reach the provider by another path, none of the mechanisms in this release apply.**
- `agentguard verify-execution` is a **preflight only**. It validates authority and deliberately does not consume the decision nonce, so it provides no replay protection. Only the protected execution lifecycle (`reserve_execution`, reached via `mcp-proxy-v2` or `agentguard-mcp-http`) claims single-use authority. Despite the name, `verify-execution` does not execute.
- A `DecisionReceipt` is a **bearer admission ticket** inside its validity window. It binds principal
  claims, not a holder key, so receipt, grant, and approval material must be handled as sensitive until
  consumed. External work on this pattern binds authority non-bearer and sink-bound, which is strictly
  stronger than what this release provides.
- **Provenance on the live MCP path is operator-declared, not inferred.** The protected adapters
  normalize a call from the wire and cannot know its origin, so `--provenance` /
  `--provenance-verified` are deployment assertions. Omitted, provenance is `unverified` and a policy
  with `unknown_provenance != allow` refuses every call. This is the adapter-as-TCB-boundary
  assumption stated in `threat-model.md`, not a derived fact.
- **The capability classifier is keyword-based and advisory.** It reads the tool name, description,
  and schemas. A provider whose description omits the words AgentGuard looks for classifies as
  `unknown` and is denied under a default-deny `unknown_capability`. That is a real ergonomic cost,
  not a bug, and it is the policy's job to decide whether to allow such a tool.
- A reconciliation resolution records **no provider operation id**. The reconciler observes it and
  folds it into `evidence_digest`, but the frozen provider contract carries only a digest, so
  `execution_resolutions.provider_operation_id_digest` stays empty (`AG-EVID-001`).
- Verified identity, field provenance, effect projection, and declared causal ancestry are only as trustworthy and complete as the integration that supplies them. AgentGuard does not infer hidden dependencies from arbitrary application memory or external systems.
- The final executor/provider adapter is trusted to invoke the exact verified operation. Operating-system sandboxing, process isolation, filesystem MAC, and network egress enforcement are outside AgentGuard.

## MCP and HTTP boundary

- The protected stdio profile is a bounded `2025-03-26` interoperability target. The protected Streamable HTTP profile is a bounded `2026-07-28` target. AgentGuard does not claim full conformance with every MCP method, extension, task/session behavior, or future protocol revision.
- Unsupported/custom protected client methods and JSON-RPC batches fail closed rather than being forwarded generically.
- Schema binding protects protocol-observable tool identity/schema state; it cannot cryptographically prove that a provider did not change hidden semantics behind an unchanged schema.
- Non-loopback HTTP binding requires in-process TLS, a non-empty Bearer access token, and an explicit non-wildcard Host allowlist. Browser-reachable mode additionally requires an Origin allowlist. External TLS termination is not currently modeled as an equivalent trusted-proxy security boundary.
- Legitimate provider tool output is not subjected to generic DLP/redaction by the MCP adapter. Secret minimization applies to AgentGuard-owned credentials, launch metadata, durable state, audit, and execution evidence.

## Credential and provider boundary

The full contract is in [credential-contract.md](credential-contract.md). The limits that matter most:

- The included production credential source resolves an explicitly configured environment-held secret
  late in the execution path. It is not a general secret vault and does not mint provider-native or
  downscoped short-lived tokens.
- **A static secret cannot be attenuated.** Because the source is one environment variable, requesting
  fewer scopes does not yield a weaker credential. AgentGuard therefore requires the requested scope
  set to exactly equal the configured profile's scopes, rather than claim least privilege it cannot
  enforce at the provider (`adapters/broker/production.py:250-252`). To narrow a credential you must
  configure a narrower secret.
- **No audience proof.** AgentGuard binds a *declared* audience to a decision. It does not
  cryptographically prove the provider will accept that audience for that token, so a misconfigured
  profile can claim an audience the provider does not enforce.
- **No revocation call.** Profile revocation is durable AgentGuard state only. A leaked secret remains
  valid at the provider until it expires.
- **No memory zeroization.** Resolved secrets are not scrubbed from process memory; Python cannot
  guarantee erasure of immutable `str` bytes (ADR 0005).
- The preserved mock broker is for demos/contract testing and must not be represented as a production
  credential provider. It ships inside the wheel because the test suite uses it; that is a packaging
  inconvenience, not an endorsement.
- The production credential authority is reachable only via `agentguard-mcp-http --credential-env`;
  `broker-demo` exercises the same contract against the mock broker with no secret source.
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
- The pre-registered authorization-lineage research program is retained in the repository as the research
  record but is excluded from the distributed wheel and sdist. It is importable only from a source
  checkout or editable install. Its result is `RESEARCH_CLAIM: NOT_VALIDATED` and
  `AGENTGUARD_SPECIFIC_DIFFERENTIATION_THESIS: FALSIFIED_WITHIN_PROTOCOL`; see
  `docs/research/FREEZE_V2_RESULT_ADJUDICATION.md`.
- `agentguard.engine.execution.authorize_execution` is a deprecated alias. It is non-consuming and
  provides no single-use enforcement; use `preflight_execution` for validation or the protected
  execution lifecycle (`reserve_execution`) to claim execution authority.
- The v1 policy model defaults `default_action` to `deny` when the key is absent. In that model
  `allowed_tools` is a narrowing check that runs first and `default_action` is only the fallback for
  tools that passed it, so a policy that wants to permit a tool must declare both. The v2 model is
  structurally default-deny (`PolicyDefaults.effect` is `Literal[Effect.DENY]`).
