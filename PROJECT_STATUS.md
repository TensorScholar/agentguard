# Project status

AgentGuard v0.2.0rc2 is an auditable release candidate for deterministic action
authorization, MCP mediation, bounded credential grants and tamper-evident
evidence. It is not a production-certified identity system, credential vault,
distributed authorization service or operating-system sandbox.

## Validated capabilities

- strict Policy v2 and ActionIntent validation;
- deterministic default-deny authorization and deny precedence;
- signed decision receipts and bounded credential-grant verification;
- atomic single-use approval and nonce state;
- fresh, per-server MCP schema and inventory isolation;
- fail-closed handling for missing, stale or changed MCP inventory;
- bounded concurrent MCP stdio relay and shutdown behavior;
- configuration posture checks for direct and parallel bypass routes;
- secret redaction before audit persistence;
- hash-chained audit records and signed external checkpoints;
- closed-world evidence bundles with optional Ed25519 attestations;
- owner-only state permissions and symlink-aware filesystem handling;
- explicit v0.1 compatibility surfaces;
- generated schemas, source distribution, wheel and container definition.

## Latest verified implementation gate

The latest audited implementation checkpoint is
`a6d35fff57670b0bd27ec50f692505360aeabe27`.

- Full test suite: 341 passed, 1 skipped.
- Branch coverage: 83%.
- Ruff: PASS.
- Strict Mypy: PASS over 62 source files.
- Generated schemas: PASS, 11 verified.
- Real MCP filesystem smoke: SKIPPED.
- Production readiness: NOT CLAIMED.

## Completed audit findings

- AG-POL-001
- AG-MCP-002
- AG-MCP-001

## Remaining audit findings

- AG-EXEC-001
- AG-CRED-001
- AG-CAN-001
- AG-RPC-001
- AG-AUD-001
- AG-AUD-002
- AG-DX-001
- AG-DX-002
- AG-ARCH-001
- AG-LOADOUT-001
- AG-REL-001
- AG-VAL-001

## Primary blocker

`AG-EXEC-001`: the implementation does not yet provide one integrated execution
boundary that coherently binds authorization, execution-time revalidation,
credential use, nonce consumption, protected action execution and terminal
audit outcome.

## Promotion boundary

Promotion requires every remaining engineering and release gate to pass,
including the integrated execution boundary, exact required GitHub status
checks, real MCP interoperability, independent security review, deployment-
specific validation and a controlled production pilot.

A release candidate must not be represented as production-certified.
