# Project Status

## Current phase

AgentGuard `v0.2.0rc3` is a hardened release candidate for deterministic runtime authorization, protected MCP execution, bounded production credential authority, durable external-effect reconciliation, and single-host multi-process service coordination.

**Production readiness is not claimed.** Engineering validation and production certification are separate gates.

## Validated engineering capabilities

- strict Policy v2 and `ActionIntent` validation with deterministic default-deny authorization;
- signed decision/approval receipts and execution-time digest revalidation;
- atomic approval use, decision nonce, authority lease, typed-release, staging, and execution reservation semantics;
- signed delegated authority, field provenance, typed releases, staged execution, declared causal ancestry, and deterministic policy/authority analysis;
- protected MCP stdio mediation with fail-closed fresh schema/inventory handling;
- bounded protected MCP `2026-07-28` Streamable HTTP execution;
- TLS/Bearer/Host requirements for non-loopback HTTP binding and Origin enforcement when configured for browser-reachable use;
- provider-neutral credential authority with late secret resolution, durable profile/revocation state, and exact provider endpoint binding;
- frozen provider/external-effect contracts with explicit idempotency/replay semantics and `RECONCILE_BEFORE_RETRY` as the safe default without stronger evidence;
- durable external-effect binding before side-effecting dispatch on the configured HTTP provider path;
- provider-specific durable reconciliation with explicit evidence trust levels and no blind redispatch;
- single-host multi-process reconciliation leases, monotonic fencing tokens, crash takeover, stale-worker rejection, startup recovery, and health/readiness probes;
- secret-minimized hash-chained audit, signed checkpoints, authenticated evidence manifests, and signed execution attestations;
- reproducible wheel/normalized-sdist validation, deterministic SBOM/release manifest generation, checksums, clean-install smoke, non-root container smoke, cross-platform CI, Security, and CodeQL gates.

## Engineering gaps closed on the current line

- `AG-EXEC-001` (Protected Execution Boundary) — protected execution boundary and durable definite/ambiguous outcome classification;
- `AG-CRED-001` (Bounded Credential Authority) — bounded production credential-authority profile with late environment-backed secret resolution and exact provider binding;
- `AG-RPC-001` (Streamable HTTP Boundary) — bounded protected Streamable HTTP service boundary with fail-closed remote-listener requirements;
- `AG-ARCH-001` (Single-Host Multi-Process Service) — explicit single-host multi-process service/reconciliation topology with transactional lease fencing.

Closing these engineering gaps does **not** imply that AgentGuard is a production-certified distributed service.

## Remaining promotion debt

- `AG-CAN-001` (RFC Canonicalization Assurance) — canonicalization assurance beyond the deliberately supported signed-schema numeric subset;
- `AG-AUD-001` / `AG-AUD-002` (Operational Durability Drills) — deployment backup/restore, independent checkpoint retention, corruption, and key-loss operational exercises;
- `AG-DX-001` / `AG-DX-002` (Operator Ergonomics) — broader operator/developer ergonomics and deployment automation;
- `AG-BROKER-001` (Provider-Native IAM Downscoping) — provider-native credential minting/downscoping and broader real-provider integration decisions;
- `AG-REL-001` (Release Signing & Provenance) — final exact-commit release evidence, release signing/provenance decision, tag/release publication, and independent artifact verification;
- `AG-VAL-001` (Independent Penetration & Pilot) — independent security review, long-duration soak testing, and controlled production pilot.

Multi-host HA, distributed consensus, generic provider output DLP, hosted identity-backed approval, and generic provider compensation are explicit non-capabilities rather than hidden claims.

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
