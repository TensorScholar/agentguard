# AgentGuard

**Deterministic action authorization and execution-integrity controls for AI agents.**

> **Release status:** `v0.2.0rc2` remains a non-production-certified release candidate. The development line includes the protected execution boundary, signed execution attestations, delegated capability leases, field-level provenance and typed releases, staged high-impact actions, declared causal execution graphs, and deterministic least-authority/policy analysis. Production promotion still requires external, provider-specific, and operational validation.

[![CI](https://github.com/TensorScholar/agentguard/actions/workflows/ci.yml/badge.svg)](https://github.com/TensorScholar/agentguard/actions/workflows/ci.yml)
[![Security](https://github.com/TensorScholar/agentguard/actions/workflows/security.yml/badge.svg)](https://github.com/TensorScholar/agentguard/actions/workflows/security.yml)
[![CodeQL](https://github.com/TensorScholar/agentguard/actions/workflows/codeql.yml/badge.svg)](https://github.com/TensorScholar/agentguard/actions/workflows/codeql.yml)

AgentGuard turns an untrusted agent action into a deterministic, signed authorization decision; constrains any credential grant to that decision; revalidates execution-time inputs; and records correlated, tamper-evident evidence.

## Why AgentGuard exists

AI-agent security controls are often split across identity, policy, credential issuance, runtime execution, and audit systems. The dangerous failures happen between those systems:

- an approved action is executed with different arguments;
- a credential exceeds the approved audience, scope, tenant, or lifetime;
- a receipt, approval, or execution permit is replayed;
- an MCP client keeps a direct route around the protected proxy;
- audit history is modified, truncated, or replaced;
- an evidence bundle is internally consistent but unauthenticated.

AgentGuard addresses these integrity gaps with deterministic controls and stable reason codes, not model judgment.

## Security objective

```text
Authorized action == Credentialed action == Executed action
Every protected MCP route passes through the enforcement path
Retained evidence is redacted, integrity-checked, and optionally signed
```

The development line now composes these controls through a protected execution boundary and can issue portable signed execution attestations. Ambiguous external outcomes remain explicit and may be reconciled later without rewriting history or redispatching the action.

## Architecture

AgentGuard is a provider-neutral modular monolith using ports and adapters. The domain and policy engine do not depend on MCP, HTTP, SQLite, Typer, OpenTelemetry, or a credential provider.

```mermaid
flowchart LR
    U[Untrusted agent or client] --> A[Protocol adapter]
    A --> N[Normalize ActionIntent]
    N --> P{Policy v2}
    P -->|Deny| D[Fail closed<br/>stable reason code]
    P -->|Approval required| H[Bounded approval receipt]
    H --> P
    P -->|Allow| R[Signed decision receipt]
    R --> B[CredentialBroker port]
    B --> G[Bounded credential grant]
    R --> E[ExecutionGuard]
    G --> E
    E --> T[Protected tool or service]
    E --> X[Execution attestation]
    E --> Q[Append-only reconciliation]
    D --> L[Hash-chained audit ledger]
    E --> L
    L --> C[Signed checkpoint<br/>evidence bundle]
```

## Core workflows

### 1. Authorize, bind, and verify

```mermaid
flowchart TD
    I[Action request] --> V[Schema and canonicalization checks]
    V --> P{Deterministic policy evaluation}
    P -->|Deny| X[Reject and audit]
    P -->|Approval required| A[Validate bounded approval]
    A --> P
    P -->|Allow| R[Issue signed short-lived receipt]
    R --> C[Request least-privilege credential grant]
    C --> B[Verify audience, scope, tenant, TTL, and attestation]
    B --> E[Revalidate exact execution intent]
    E --> N[Atomically consume execution nonce]
    N --> O[Invoke protected action]
    O --> Z[Record terminal audit outcome and evidence]
```

### 2. Protect MCP tool calls

```mermaid
flowchart TD
    C[MCP client configuration] --> S[mcp-posture scan]
    S -->|Direct, parallel, ambiguous, or invalid route| F[Fail the posture gate]
    S -->|Protected route| P[AgentGuard MCP proxy]
    P --> I[Fetch fresh per-server tool inventory and schema]
    I -->|Missing, stale, or inconsistent| A[Fail closed or require approval]
    I -->|Trusted| D[Authorize tools/call]
    D --> R[Relay bounded request and response]
    R --> L[Redact and append audit evidence]
```

### 3. Preserve audit and evidence integrity

```mermaid
flowchart LR
    E[Security event] --> R[Redact secrets]
    R --> L[Append hash-chained ledger record]
    L --> V[Verify retained chain]
    V --> C[Create signed checkpoint]
    C --> X[Export to independently controlled storage]
    L --> B[Build closed-world evidence bundle]
    B --> M[Authenticate manifest]
```

## Implemented capabilities

- Strict versioned schemas for intent, policy, receipts, credentials, execution, audit, and evidence.
- Policy v2 with default deny, deterministic deny precedence, tenant binding, provenance conditions, and blast-radius budgets.
- Ed25519-signed, short-lived, request-bound decision and approval receipts.
- Full-intent canonical digests plus diagnostic field digests.
- Approval budgets that cannot expand the original decision.
- Credential ceilings for audience, scope, tenant, TTL, and decision validity.
- Atomic issuance, approval-use, and execution-nonce state in SQLite.
- MCP stdio mediation with bounded messages, concurrent relay, stable server identity, and fail-closed schema behavior.
- Configuration posture checks for direct and parallel bypass routes.
- Sensitive-path, encoded-path, raw-host, decimal-IPv4, and cloud-metadata protections.
- Secret redaction at the audit persistence boundary.
- Owner-only permissions for private keys, ledgers, and generated evidence on POSIX systems.
- Hash-chained audit events, signed external checkpoints, and authenticated evidence manifests.
- Compatibility commands for the preserved v0.1 scanner, gate, approval, proxy, and reporting workflows.
- Portable Ed25519-signed execution attestations with offline verification and digest-linked history.
- Append-only reconciliation for `UNKNOWN` outcomes without automatic redispatch or historical state rewriting.
- Signed attenuating authority graphs with revocation cascades and bounded consumable capability leases.
- Atomic capability-lease consumption in the same reservation transaction as execution nonce claiming.
- Signed field-level provenance with transformation lineage and exact-value typed releases consumed with execution reservation.
- Staged high-impact execution with bounded prepare/commit windows, cancellation, and commit-time security revalidation.
- Secret-minimized declared causal execution graphs with ancestry/depth/label enforcement across protected actions.
- Deterministic minimal-authority and policy-counterfactual analysis that never overrides the enforcement engine.

## Quick start

AgentGuard requires Python 3.11 or newer.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .

agentguard init
agentguard demo --output .agentguard/demo
agentguard evidence-verify .agentguard/demo/evidence \
  --public-key .agentguard/demo/public.pem \
  --require-signature
```

## Authorize, broker, and verify

```bash
agentguard authorize \
  examples/scoped-refund/request.json \
  examples/scoped-refund/policy.yaml \
  --output decision.json

agentguard broker-demo \
  examples/scoped-refund/request.json \
  decision.json \
  --output grant.json

agentguard verify-execution \
  examples/scoped-refund/request.json \
  decision.json \
  examples/scoped-refund/policy.yaml \
  --grant grant.json
```

The included broker is a contract-test and demonstration adapter. It is not a production credential-provider integration.

## Check MCP enforcement posture

```bash
agentguard mcp-posture \
  --config examples/mcp_posture_protected.json \
  --fail-on-bypass
```

The command fails when it detects a direct route, an invalid route, an unverifiable proxy target, or a guarded-plus-direct duplicate.

## Product boundary

AgentGuard owns:

- action normalization and deterministic authorization;
- signed receipt and approval integrity;
- credential ceilings and grant verification;
- execution-time binding and replay controls;
- MCP enforcement posture;
- local audit, checkpoint, and evidence correlation.

AgentGuard does not own:

- model evaluation or agent orchestration;
- identity proofing or a secret vault;
- a hosted human-approval interface;
- SIEM storage or distributed consensus;
- operating-system sandboxing, process isolation, or network egress control.

A protocol adapter can enforce only traffic routed through it. Configuration scanning reduces blind spots but cannot prove that no hidden or dynamically constructed route exists.

## Current limitations

- SQLite replay, approval, issuance, reconciliation, capability-lease, typed-release, staging, and causal-ledger semantics are single-node.
- Field provenance and causal ancestry are only as complete as the trusted integration that declares and signs them; AgentGuard does not infer hidden dependencies from arbitrary external systems.
- `REVERSIBLE` / `COMPENSATABLE` staging classifications do not provide generic provider-side undo; compensation requires a provider-specific contract.
- Policy intelligence is deterministic advisory analysis. It does not synthesize or silently modify enforcement policy and does not place an LLM in the trusted decision path.
- The HTTP package provides validation primitives, not a complete production proxy.
- No live production credential-provider adapter is included.
- No identity-backed interactive approval service is included.
- No external penetration test, long-duration soak test, or controlled production pilot has been completed.
- Multi-replica deployment requires shared transactional state, centralized signing, policy distribution, and operational rollback controls.

See [project status](docs/project-status.md) and [known limitations](docs/limitations.md) for the complete promotion boundary.

## Documentation

| Document | Purpose |
|---|---|
| [Architecture](docs/architecture.md) | Components, ports, adapters, and transaction semantics |
| [Project status](docs/project-status.md) | Validated capabilities, open findings, and promotion gates |
| [Threat model](docs/threat-model.md) | Protected properties, trust boundaries, threats, and residual risk |
| [Limitations](docs/limitations.md) | Explicit technical and operational constraints |
| [Production deployment](docs/production-deployment.md) | Deployment profiles and promotion requirements |
| [Release process](docs/release-process.md) | Release validation and artifact handling |
| [v1 to v2 migration](docs/migration-v1-to-v2.md) | Compatibility and migration guidance |
| [Demo](docs/DEMO.md) | Local demonstration workflow |

## Development

```bash
python -m pip install -e '.[dev]'
make check
```

Security-sensitive changes must include tests for allow, deny, replay, mutation, stale-state, and failure behavior where applicable. See [.github/CONTRIBUTING.md](.github/CONTRIBUTING.md).

## Security

Do not report vulnerabilities in public issues. Follow [.github/SECURITY.md](.github/SECURITY.md).

## License

MIT. See [LICENSE](LICENSE).
