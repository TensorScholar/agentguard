# Project status

AgentGuard v0.2.0rc2 is a hardened, locally validated release candidate for decision-bound agent
actions and MCP enforcement coverage. It is not a production-certified identity, credential vault,
distributed authorization service or operating-system sandbox.

## Demonstrated in this repository

- strict Policy v2 and ActionIntent validation;
- deterministic default-deny authorization and deny precedence;
- complete signed intent binding and execution-time policy revalidation;
- approval budgets constrained by the originating decision;
- credential audience, scope, tenant, TTL and decision-window ceilings;
- atomic single-use credential issuance, approval consumption and nonce consumption;
- fresh MCP schema/inventory resolution with missing, stale and changed states failing closed;
- bounded and concurrent MCP stdio relay behavior;
- stable per-server identities for MCP inventory and local approval grants;
- configuration-level detection of direct and parallel MCP bypass routes;
- defense-in-depth redaction before legacy audit persistence;
- private SQLite/key/evidence file permissions and symlink-aware file handling;
- retained legacy audit sanitization with explicit anchor invalidation acknowledgement;
- hash-chained audit records and signed external checkpoints;
- closed-world evidence bundles with optional Ed25519 manifest attestations;
- preserved v0.1 scanner, gate, reporting, doctor and compatibility commands;
- generated JSON schemas, source distribution, wheel and container definition.

## Validation boundary

The RC2 source is validated locally on Linux with Python 3.13: 314 tests passed, one opt-in real-MCP
smoke was skipped, and source-only branch-traced coverage reached 85.27% statements, 71.23% branches
and 81.94% combined. The imported RC1 evidence contains successful macOS/Python 3.12 validation, but
RC2 changes require their own public CI run on Linux, macOS and Windows. See
`docs/validation-rc2.md` for the exact boundary.

## Not demonstrated

- independent penetration test or formal verification;
- production Streamable HTTP reverse proxy;
- distributed nonce/approval state across replicas;
- live credential-broker or Loadout sandbox integration;
- end-to-end identity proofing and role-backed human approval UI;
- proof that every undisclosed network route is intercepted;
- production workload soak test and disaster-recovery exercise;
- externally operated audit checkpoint storage.
