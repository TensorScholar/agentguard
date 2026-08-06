# Project Status

## Current phase

AgentGuard `v0.2.0rc2` is a hardened release candidate for deterministic action authorization, MCP mediation, bounded credential grants, replay control, and tamper-evident evidence.

**Production readiness is not claimed.**

## Validated capabilities

- strict Policy v2 and ActionIntent validation;
- deterministic default-deny authorization and deny precedence;
- signed decision and bounded approval receipts;
- bounded credential-grant verification;
- atomic issuance, approval-use, and execution-nonce state;
- fresh per-server MCP schema and inventory isolation;
- fail-closed handling for missing, stale, or inconsistent MCP inventory;
- bounded concurrent MCP stdio relay and shutdown behavior;
- configuration checks for direct and parallel bypass routes;
- secret redaction before audit persistence;
- hash-chained audit records and signed external checkpoints;
- closed-world evidence bundles with optional Ed25519 attestations;
- owner-only state permissions and symlink-aware filesystem handling;
- generated schemas, package artifacts, and a non-root container definition.

## Primary blocker

`AG-EXEC-001`: the project does not yet provide one integrated execution boundary that coherently binds:

1. authorization;
2. execution-time revalidation;
3. credential use;
4. approval and nonce consumption;
5. protected action execution;
6. terminal audit outcome.

The individual controls exist, but a production claim requires one fail-closed orchestration path that proves they cannot be bypassed or reordered.

## Remaining findings

- `AG-EXEC-001` — integrated execution boundary;
- `AG-CRED-001` — production credential profile or explicit no-broker profile;
- `AG-CAN-001` — canonicalization assurance;
- `AG-RPC-001` — complete production HTTP/RPC boundary;
- `AG-AUD-001` and `AG-AUD-002` — audit durability and operational assurance;
- `AG-DX-001` and `AG-DX-002` — operator and developer experience;
- `AG-ARCH-001` — production architecture boundary;
- `AG-BROKER-001` — production broker decision;
- `AG-REL-001` — release promotion controls;
- `AG-VAL-001` — external validation.

## Promotion boundary

Production promotion requires all of the following for the exact release commit and artifacts:

- integrated secure execution boundary;
- exact required CI and security checks;
- reproducible wheel and source-distribution validation;
- real MCP client and downstream-server interoperability tests;
- deployment-specific bypass scanning;
- protected signing-key and checkpoint operations;
- backup, restore, corruption, and key-loss exercises;
- independent security review;
- long-duration soak testing;
- a controlled production pilot with no unresolved critical findings.

Until those gates pass, AgentGuard must be represented as a release candidate.
