# Architecture

AgentGuard is a modular monolith using ports and adapters. The domain and engine are deterministic and have no dependency on SQLite, HTTP, MCP, Typer, OpenTelemetry or any credential provider.

```text
Protocol adapter -> ActionIntent -> Policy engine -> DecisionReceipt
                                        |                |
                                        v                v
                                  approval path    CredentialBroker
                                                         |
                                                         v
                                                 ExecutionGuard
                                                         |
                                                         v
                                                   Audit evidence
```

The package follows a functional-core/imperative-shell split. All security decisions are explainable through stable reason codes. External systems are connected only through typed ports.

Credential issuance is claimed atomically before a broker is invoked. A single-use decision keeps
that claim even when the broker fails, so an outage cannot turn into an unbounded retry channel.
Multi-use decisions may retry with a new credential request while the decision remains valid, but
each attempt consumes one approval use when approval is required. Execution nonce consumption is a
separate transaction and is never used as a substitute for issuance consumption.

Broker grants carry a provider-neutral Ed25519 attestation in the mock adapter. The authenticated
payload binds the broker and key identity, decision and trace, issuance identifier, audience,
scopes, tenant, mode, timestamps, and a digest of the opaque handle. Production adapters may use a
different authentication mechanism only through an explicit trusted `BrokerGrantVerifier` port.

The v2 MCP adapter obtains each `tools/call` schema through a `ToolSchemaResolver`. The included
resolver projects the preserved v0.1 discovered inventory into the v2 path. Missing, stale, or
digest-inconsistent schemas require approval before authorization; the adapter never substitutes an
empty schema for an allowed call.

The v0.1 stdio relay defines audit order as durable SQLite append order. Causality is guaranteed
within one request (for example, `ALLOW` precedes response `REDACT`), while independent concurrent
requests may interleave. Shutdown uses an idle-output deadline plus a hard upper bound: active
server output extends the graceful drain window, but a hung or endlessly streaming child is still
terminated within the bound.

## Protected MCP v2 execution profile

`agentguard mcp-proxy-v2` is an explicit, ENFORCE-only stdio profile layered on the v0.2
execution-integrity boundary. It does not replace the preserved `agentguard mcp-proxy` v0.1 route.
The initial profile interoperates only with a negotiated `2025-03-26` protocol version; this is a
bounded interoperability target, not a claim of full MCP 2025-03-26 conformance and not an
implementation of later MCP task/session semantics.

A protected `tools/call` is authorized and then executed through
`AgentGuardService.execute_protected()`. `MCPProtectedExecutor` receives only `VerifiedExecution`
and constructs a new downstream JSON-RPC request from the verified server/tool/arguments. The
downstream request id is the AgentGuard `execution_id`; the client request id remains only in the
connection-local correlation registry used to return a response to the caller.

Each launched subprocess receives a unique `server_instance_id`. The verified MCP resource binds the
logical `server_id`, that process-instance id, and a non-secret launch fingerprint derived from a
secret-minimized argv representation, resolved executable when available, and working directory.
Tool schemas are populated only from validated `tools/list` responses observed from that process
instance. Pagination must complete before a schema is usable. `notifications/tools/list_changed`
invalidates the inventory, and the last observed schema digest is checked again immediately before
write. This closes the adapter-visible inventory race but does not cryptographically prove that a
server's hidden semantics did not change outside protocol-observable schema state.

The initial protected client-to-server method surface is deliberately narrow:

| Method | Protected v2 behavior |
| --- | --- |
| `initialize` | Reconstructed passthrough; records requested protocol profile |
| `notifications/initialized` | Reconstructed passthrough |
| `ping` | Reconstructed passthrough |
| `tools/list` | Reconstructed passthrough; validated responses populate instance-bound schema cache |
| `tools/call` | Never passthrough; executes through `execute_protected()` |
| `notifications/cancelled` | Reconstructed only for a known protected call, translating client id to `execution_id` |
| Any other/custom client method | Fail closed / not forwarded |
| JSON-RPC batches | Unsupported; never forwarded |

For `tools/call`, only `name`, `arguments`, and `_meta.progressToken` are recognized. The progress
token is intentionally omitted from the reconstructed protected downstream request. Other extension,
task, or execution-affecting fields fail closed.

Protected responses are intercepted by `execution_id` before the generic server relay. Concurrent
responses may arrive out of order but are delivered only to their owning protected execution. A
valid result maps to `SUCCEEDED`; `isError=true` or a valid JSON-RPC error maps to `FAILED`; and any
ambiguous failure at or after the write attempt maps to `UNKNOWN`. `FAILED` is a definite failure
classification, not a retry-safety assertion. Legitimate provider tool results are returned without
generic output redaction; AgentGuard-owned credentials, signing material, and internal secrets are
never inserted into those responses or raw execution state.

## Signed execution attestations and reconciliation

Phase 5C adds a portable evidence layer above the durable execution ledger. An
`ExecutionAttestation` signs a canonical, secret-minimized payload containing the execution and
decision correlation, intent and authority digests, policy digest when retained, lifecycle state,
terminal metadata, the latest append-only reconciliation resolution, and the previous attestation
digest. Raw tool arguments, credential handles, provider-operation identifiers, and provider
responses are not embedded in the attestation.

Attestations are signed with an explicit attestation signer and may be verified offline from the
artifact plus a trusted public key. Attestations for one execution can form a digest-linked chain;
issuing a later attestation after reconciliation does not invalidate or replace the earlier
artifact.

Reconciliation is deliberately separate from execution state. An execution that was durably
classified `UNKNOWN` remains `UNKNOWN`; later provider evidence is stored as an immutable
`ExecutionResolution` (`CONFIRMED_SUCCEEDED`, `CONFIRMED_FAILED`, `STILL_UNKNOWN`, `UNSUPPORTED`,
or `CONFLICT`). Reconciliation never invokes a protected executor and never redispatches an action.
Conflicting confirmed evidence is persisted as an explicit conflict rather than last-write-wins.
Provider operation identifiers are persisted only as digests. Reconciliation evidence carries an
explicit assurance level: `AGENTGUARD_SIGNED` for AgentGuard-authenticated observations,
`PROVIDER_CORRELATED` for evidence tied to a provider operation without a trusted provider truth
assertion, and `PROVIDER_VERIFIED` for evidence produced by a reconciler whose provider verification
contract is independently trusted. Only `PROVIDER_VERIFIED` evidence may classify an `UNKNOWN`
execution as `CONFIRMED_SUCCEEDED` or `CONFIRMED_FAILED`.

## Delegated authority graph and capability leases

Phase 5D adds signed `AuthorityGrant` nodes and bounded `CapabilityLease` execution authority.
Root grants bind a principal to an explicit `CapabilityScope`. Delegated grants point to their
parent, remain within the same tenant, cannot outlive the parent, and must monotonically attenuate
the parent's capabilities, protocol/server/tool/operation/resource scope, call budget, and
delegation properties.

An authority-bearing `ActionIntent` contains only an `AuthorityReference`: leaf grant id, lease id,
and digest of the verified root-to-leaf chain. Authorization and protected execution independently
reload and verify the active chain, signatures, subject binding, scope, chain digest, and lease.
`AgentGuardService(require_authority=True)` provides an opt-in fail-closed deployment mode in which
a missing authority reference is rejected before policy evaluation; the default remains compatible
with Phase 5A/5B callers that do not yet supply delegated authority.
The lease use is consumed atomically in the same SQLite transaction that claims the decision nonce
and creates the `RESERVED` execution record. This makes the last lease use a one-winner operation
under concurrency.

Revoking a grant recursively revokes active descendant grants and their active leases. Revocation
therefore closes the race between a parent revocation and a later leaf execution reservation. The
execution ledger stores only grant/lease identifiers and the chain digest; it does not persist the
full graph inside each execution record.
