# Architecture

AgentGuard is a provider-neutral modular monolith using ports and adapters. The deterministic domain and policy engine have no dependency on SQLite, HTTP, MCP, Typer, OpenTelemetry, or a credential provider. External systems enter through typed ports; adapters own protocol parsing, storage, signing, credential resolution, and provider I/O.

## Current execution model

```text
Untrusted proposal
      |
      v
Protocol adapter -> normalized ActionIntent -> deterministic Policy v2
                                              |
                                              v
                                      signed DecisionReceipt
                                              |
                +-----------------------------+-----------------------------+
                |                                                           |
                v                                                           v
       credential authority                                      execution-time revalidation
                |                                                           |
                +-----------------------------+-----------------------------+
                                              |
                                              v
                                      durable RESERVED/DISPATCHING
                                              |
                                              v
                                  durable ExternalEffectBinding
                                              |
                                              v
                                      provider / MCP tool
                                              |
                               +--------------+--------------+
                               |                             |
                               v                             v
                       SUCCEEDED / FAILED                  UNKNOWN
                                                             |
                                                             v
                                                  provider reconciliation
                                                             |
                                                             v
                                                append-only resolution evidence
```

The package follows a functional-core/imperative-shell split. Security decisions use stable reason codes. Durable state is responsible for atomic use-count, replay, staging, lease, and reconciliation ownership semantics.

## Authorization and authority

Policy v2 is deterministic and default-deny. Signed decision receipts bind the normalized request, policy result, validity, approval context, and execution-security digests. Execution revalidates the current intent before consuming authority.

Delegated authority is represented by signed attenuating `AuthorityGrant` chains and bounded `CapabilityLease` objects. A protected execution atomically claims the decision nonce and applicable consumable authority in the same reservation transaction. Revocation cascades to active descendants. `require_authority=True` enables deployments that require an authority reference on every protected action; workload identity proofing remains an external control.

Field-integrity constraints use signed provenance statements and exact-value typed release receipts. Causal execution ancestry is explicitly declared and persisted as secret-minimized identifiers/digests; AgentGuard does not infer undeclared external dependencies.

High-impact staged execution separates durable prepare from commit. Commit re-runs security checks inside its bounded window before entering the normal protected execution path. Staging classifications are control semantics, not generic provider undo.

## Protected MCP profiles

### Protected stdio

`agentguard mcp-proxy-v2` is an ENFORCE-only protected stdio profile layered on the execution-integrity boundary. Its initial interoperability profile is bounded to MCP `2025-03-26`; unsupported/custom methods and JSON-RPC batches fail closed.

Each subprocess receives a unique server-instance identity. Tool schemas become usable only after validated `tools/list` observations for that instance, complete pagination, freshness checks, list-change invalidation, and a final observed digest check. This closes adapter-visible inventory races without claiming that hidden provider semantics cannot change behind an unchanged schema.

Protected `tools/call` is reconstructed from the verified server/tool/arguments and dispatched through `AgentGuardService.execute_protected()`. The downstream request id is the AgentGuard execution id, allowing transport responses to correlate with the durable execution record.

### Protected Streamable HTTP

The bounded modern HTTP profile targets MCP `2026-07-28`. It retains protected `tools/call` semantics, message/response size limits, endpoint identity binding, and request security checks.

Loopback is the default service boundary. A non-loopback listener is accepted only with:

- a non-empty Bearer access token;
- an explicit non-wildcard Host allowlist;
- an in-process TLS certificate and private key;
- an explicit Origin allowlist when Origin enforcement/browser-reachable mode is enabled.

`/livez` reports process liveness. `/readyz` runs a non-mutating durable-state readiness probe and returns 503 on dependency failure. `/healthz` remains as the compatibility endpoint.

## Production credential authority

Phase 6 separates authorization from provider secret material. `CredentialAuthorityProfile` binds an AgentGuard credential profile to an exact provider identity, tenant, audience, scopes, endpoint digest, source binding, and injection shape.

The included production-profile source resolves an explicitly named environment secret only when credential material is needed. Durable grants/profile state retain binding metadata and digests, not the provider secret. Brokered grants remain bounded by the signed decision and are independently verified before use. Revocation is durable.

This is a provider-neutral authority boundary, not a claim that AgentGuard includes every provider's native token-minting or secret-management service.

## Provider/external-effect contract

Before side-effecting dispatch on the configured provider path, AgentGuard persists an `ExternalEffectBinding` that correlates the execution, decision, intent digest, provider identity, endpoint/effect identity, attempt lineage, idempotency mechanism, and replay policy without persisting raw provider credentials.

The contract distinguishes:

- no proven idempotency;
- provider-key idempotency with a bound key digest;
- same-key replay where explicitly supported;
- replay forbidden where provider semantics require it.

Without evidence that replay is safe, the default policy is `RECONCILE_BEFORE_RETRY`.

## Durable provider reconciliation

An execution that reached ambiguous provider I/O remains durably `UNKNOWN`. Reconciliation is a separate append-only evidence lifecycle; it never rewrites the original execution state and never redispatches automatically.

Provider evidence carries an explicit trust level:

- `AGENTGUARD_SIGNED` — AgentGuard-authenticated observation;
- `PROVIDER_CORRELATED` — correlated provider operation evidence without a trusted provider truth assertion;
- `PROVIDER_VERIFIED` — evidence from a reconciler whose provider verification contract is independently trusted.

Only `PROVIDER_VERIFIED` evidence may confirm an `UNKNOWN` execution as succeeded or failed. Conflicting confirming evidence becomes an explicit conflict rather than last-write-wins. Provider operation identifiers are persisted as digests.

## Single-host multi-process reconciliation

Multiple reconciliation processes coordinate through durable SQLite leases. Acquisition uses SQLite transactional locking; every takeover receives a monotonically newer fencing token. Authoritative resolution commits revalidate owner, token, and expiry in the same transaction that writes the resolution.

A stale worker may have observed provider evidence before losing its lease, but it cannot commit authoritative resolution state after expiry/takeover. The one-shot operator reconciliation CLI and background worker participate in the same ownership protocol.

This is intentionally a **single-host, multi-process** contract. It is not distributed consensus and does not claim correctness for network filesystems or independent hosts. A future shared-state adapter must preserve the same atomic reservation and fencing invariants.

## Audit and evidence

Security events are secret-minimized before persistence. The local ledger is hash chained; signed checkpoints provide retained-prefix evidence when exported to independently controlled storage. Evidence bundles may authenticate their manifest. Signed execution attestations carry secret-minimized execution/decision correlation and can form digest-linked history across later reconciliation.

Evidence authenticity proves what the trusted signer/reconciler asserted. It does not independently prove the external-world business truth of an unsigned provider event.

## Release architecture

The release candidate is validated through separate gates:

- Linux quality on Python 3.11/3.12/3.13;
- Linux/macOS/Windows compatibility on Python 3.13;
- Security dependency/static/secret/architecture scans;
- CodeQL;
- repeated wheel build byte comparison and normalized-sdist comparison;
- deterministic SBOM, release manifest, and SHA-256 checksums;
- base-wheel and HTTP-extra clean-install smoke;
- non-root container build/smoke.

These gates establish engineering evidence for an exact commit. They do not replace external penetration testing, soak testing, deployment-specific threat review, or a production pilot.
