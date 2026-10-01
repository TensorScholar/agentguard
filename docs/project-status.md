# Project Status

## Current phase

AgentGuard `v0.2.0rc4` is an engineering-validated **release candidate**. It implements the product
wedge — decision-bound credential ceilings with late secret resolution, execution-time digest
revalidation with single-use claim, durable external-effect binding with reconcile-before-retry, and a
hash-chained ledger with offline-verifiable evidence — behind protected MCP stdio and bounded
Streamable HTTP adapters, on a single host.

**Production readiness is not claimed.** Engineering validation and production certification are
separate gates, and neither is complete: there has been no independent security review, no
long-duration soak test, no controlled production pilot, and no green hosted CI run.

## Delivery history

| Phase | Scope | State |
|---|---|---|
| 0 | Stabilization and honesty | Complete. Research outcome published, v1 policy default closed, preflight rename, research code excluded from the distribution, CI/CodeQL corrected, Dependabot and build-backend hash pinning, ADR supersession recorded. |
| 1 | Product wedge | Complete. Thesis narrowed to four mechanisms, six non-goals stated first, happy path collapsed to four steps, advanced surfaces demoted from primary docs without removing code. |
| 2 | Practical MVP of the wedge | Complete. Five happy-path gaps fixed, runnable harness demo, credential failure codes surfaced, clean CLI error reporting. |
| 3 | Packaging and positioning | In progress. Version cut to `0.2.0rc4` so the Phase 0–2 work is pinnable; external evaluation path, collaboration brief, and FAQ. |

`0.2.0rc4` is the release candidate that contains Phases 0–2. Before it, `0.2.0rc3` was the current
version and contained none of them, so `0.2.0rc3` and `0.2.0rc4` are **not** interchangeable.

## Validated engineering capabilities

Ordered by what this release line leads with. The first group is the product; the second is
retained advanced surface that no product claim depends on.

**Product wedge:**

- strict Policy v2 and `ActionIntent` validation with deterministic default-deny authorization;
- signed decision/approval receipts and execution-time digest revalidation against the live call;
- atomic approval use, decision nonce, execution reservation, and lock-safe serialized dispatch
  admission semantics;
- provider-neutral credential authority with late secret resolution, durable profile/revocation
  state, and exact provider endpoint binding; ceiling issuance, enforcement, and non-persistence of
  secret material;
- frozen provider/external-effect contracts with explicit idempotency/replay semantics and
  `RECONCILE_BEFORE_RETRY` as the safe default without stronger evidence;
- durable external-effect binding before side-effecting dispatch on the configured HTTP provider path;
- provider-specific durable reconciliation with explicit evidence trust levels, terminal resolution
  exclusion with operator recheck, and no blind redispatch;
- protected MCP stdio mediation and bounded protected MCP `2026-07-28` Streamable HTTP execution, both
  with fail-closed fresh schema/inventory handling;
- TLS/Bearer/Host requirements for non-loopback HTTP binding and Origin enforcement when configured for
  browser-reachable use;
- secret-minimized hash-chained audit and verifiable evidence manifests (with optional signature
  authentication) supporting offline third-party verification;
- dedicated provider-result hashing isolated from signing canonicalization, supporting finite JSON
  floating-point provider responses.

**Advanced surface — retained, supported, not the product:**

- signed delegated authority, capability leases, field provenance, typed releases, staged execution,
  declared causal ancestry, and deterministic policy/authority analysis;
- single-host multi-process reconciliation leases, monotonic fencing tokens, crash takeover,
  stale-worker rejection, explicit operator recovery (automatic startup recovery disabled),
  claimed-attempt quota bounding, process-local round-robin fairness, and health/readiness probes;
- signed checkpoints and signed execution attestations;
- reproducible wheel/normalized-sdist validation, deterministic SBOM/release manifest generation,
  checksums, clean-install smoke, non-root container smoke, and Security and CodeQL workflow
  definitions.

### CI evidence status

Hosted CI has **not** produced a green run on this line. The PR #14 GitHub Actions runs were
runner-less infrastructure failures (`steps=[]`, `runner_id=0`) and therefore provide neither
passing-CI evidence nor code-regression evidence. Until a green run exists on the release commit,
"cross-platform CI gates" must not be cited as a validated capability.

What *has* been verified is the local execution of the same gate that CI runs: `make check`
(`ruff format --check`, `ruff check`, `mypy --strict`, `coverage` with the 80% combined
statement/branch floor, schema drift check, architecture/secret/static security scans, release
metadata consistency, and `compileall`) passes on the working tree, and the built wheel excludes
`agentguard.research` and installs and runs clean.

CodeQL is now configured to publish results with `security-events: write` and no
`continue-on-error`, so a finding can fail the check. It has not yet been observed failing or
passing on a hosted run.

## Engineering gaps closed on the current line

- `AG-EXEC-001` (Protected Execution Boundary) — protected execution boundary and durable definite/ambiguous outcome classification;
- `AG-CRED-001` (Bounded Credential Authority) — bounded production credential-authority profile with late environment-backed secret resolution and exact provider binding;
- `AG-RPC-001` (Streamable HTTP Boundary) — bounded protected Streamable HTTP service boundary with fail-closed remote-listener requirements;
- `AG-ARCH-001` (Single-Host Multi-Process Service) — explicit single-host multi-process service/reconciliation topology with transactional lease fencing.

Closing these engineering gaps does **not** imply that AgentGuard is a production-certified distributed service.

## Remaining promotion debt

Open and visible. Nothing below is claimed as done.

**Blocking an external pilot:**

- `AG-VAL-001` (Independent Penetration & Pilot) — independent security review, long-duration soak
  testing, and a controlled production pilot. This is the real gate.
- `AG-CI-001` (Hosted CI Evidence) — a green hosted CI run on the release commit, including the
  cross-platform `compatibility` and `quality` matrices. The workflow definitions are corrected and
  CodeQL is able to fail a build, but hosted runs have failed on runner capacity
  (`steps=[]`, `runner_id=0`). `make check` passes locally on the release commit; that is not the same
  as green hosted CI and is not described as such.

**Blocking a production claim about the credential path:**

- `AG-BROKER-001` (Audience Proof & Native Downscoping) — no cryptographic proof that a provider will
  honor a declared audience, and no provider-native token minting. Because a static secret cannot be
  attenuated, a narrower credential requires configuring a narrower secret. Also no upstream
  revocation call.

**Engineering debt, not blocking:**

- `AG-CAN-001` (RFC Canonicalization Assurance) — canonicalization assurance beyond the deliberately
  supported signed-schema numeric subset. This one carries security weight: all signature material and
  all digest binding depend on the canonicalizer, so a divergence is a forgery surface, not a
  compliance item.
- `AG-AUD-001` / `AG-AUD-002` (Operational Durability Drills) — backup/restore, independent checkpoint
  retention, corruption, and key-loss exercises.
- `AG-DX-001` / `AG-DX-002` (Operator Ergonomics) — the capability classifier is keyword-based and
  advisory, and provenance on the live MCP path is operator-declared. Both are ergonomics and trust
  costs, documented in `docs/limitations.md`.
- `AG-EVID-001` (Provider Operation Id in Resolutions) — the reconciler observes the provider operation
  id and folds it into `evidence_digest`, but the contract frozen by ADR 0004 carries only a digest,
  so `execution_resolutions.provider_operation_id_digest` is always empty.
- `AG-SUP-001` (Dependency Hash Pinning) — the build backend is hash-pinned; the runtime closure is
  pinned by exact version only, because `cryptography` and `cffi` ship platform-specific wheels whose
  hashes must be collected per platform.
- `AG-REL-001` (Release Signing & Provenance) — tag and release publication, release signing
  provenance, and independent artifact verification. `0.2.0rc4` is built and verified locally but is
  **not yet tagged or published**.
- `AG-TEST-001` (Fuzzing / Property-Based Tests) — the credential, policy, and MCP header parsers have
  no property-based campaign. For a project whose thesis is parsing untrusted structured input
  correctly, this is the largest methodological gap.

Multi-host HA, distributed consensus, generic provider output DLP, hosted identity-backed approval,
generic provider compensation, and a vault or token-minting product are explicit non-capabilities
rather than hidden claims.

## Promotion boundary

Production promotion requires all of the following for the **exact release commit and artifacts**:

1. required CI, Security, and CodeQL checks pass on that exact commit;
2. release metadata is internally consistent and generated schemas have no drift;
3. wheel reproducibility and normalized-sdist reproducibility pass;
4. base-wheel and HTTP-extra clean-install smoke pass, including installed service/reconciliation entrypoints;
5. deterministic SBOM, release manifest, and SHA-256 checksums are retained with the release artifacts;
6. the non-root container image builds and passes its smoke checks;
7. controlled real MCP client/downstream interoperability and failure-path tests cover the deployment profile;
8. deployment-specific bypass posture, key custody, checkpoint export, backup/restore, corruption, and key-loss procedures are exercised;
9. an independent security review and long-duration soak test complete without unresolved critical findings;
10. a controlled production pilot completes without unresolved critical findings.

Until those gates pass, AgentGuard must be represented as a release candidate.
