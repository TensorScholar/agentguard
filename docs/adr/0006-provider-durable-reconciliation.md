# ADR 0006: Provider-Specific Durable Reconciliation

- Status: Accepted for Phase 6D; **§7 (operator-triggered reconciliation) superseded by
  [ADR 0007](0007-service-multiprocess-deployment.md)**
- Date: 2026-09-02
- Depends on: ADR 0004 provider/external-effect contract freeze and ADR 0005 production credential authority

> **Supersession note.** Sections 1–6 of this ADR stand. Section 7's scoping decision — that
> continuous workers, leases, scheduling, and multi-process ownership are Phase 6E concerns — is
> superseded by ADR 0007, which introduced single-host multi-process reconciliation leases with
> monotonic fencing tokens and a background reconciliation worker. That ADR also records (Q04-02) the
> removal of automatic startup recovery, because executor liveness cannot be established from shared
> local state.

## Context

DecisionLock already classifies ambiguous protected dispatches as `UNKNOWN` and forbids blind automatic
retry. The generic Phase 5 reconciliation lifecycle can append durable resolution evidence, but it
predates the frozen provider/external-effect contract and does not itself prove that provider evidence
belongs to the exact dispatch attempt that became ambiguous.

Phase 6D closes that gap without weakening the Phase 5 execution ledger or inventing provider truth
from transport observations.

## Decision

### 1. Provider reconciliation state is a separate durable sidecar

Phase 6D does not migrate or rewrite the frozen `action-integrity.sqlite` execution schema. Provider
bindings and provider-specific evidence live in a separate SQLite store.

The sidecar persists only:

- the frozen non-secret `ExternalEffectBinding`;
- its canonical binding digest;
- provider identity digest and logical operation identity;
- digest-only `ProviderReconciliationEvidence` metadata;
- timestamps needed for durable evidence ordering.

Provider response bodies, raw credentials, credential handles, and provider secrets are not persisted.

The Phase 5 execution table remains authoritative for execution lifecycle state. The existing generic
execution-resolution table remains authoritative for the final reconciliation history consumed by
attestation.

### 2. The external-effect binding is durable before provider dispatch

For protected MCP HTTP execution, DecisionLock records the exact `ExternalEffectBinding` after the core
execution has entered durable `DISPATCHING` state but before provider credential resolution and before
the first side-effecting provider `send`.

If binding persistence fails, dispatch fails definitively before any external request is sent. Phase 6D
therefore does not introduce a new ambiguity window in which an external effect may happen without a
durable correlation binding.

The first attempt records:

- the exact provider identity;
- decision and intent identity;
- action, resource, and argument digests;
- optional verified non-secret credential binding;
- a stable logical MCP operation identity;
- a first-attempt identity whose start time equals the core durable `dispatching_at` timestamp;
- default `reconcile_before_retry` semantics when no idempotency mechanism has been proven.

### 3. Provider adapters consume the frozen binding, not caller input

A `ProviderExecutionReconciler` receives only the immutable `ExternalEffectBinding`. Provider-specific
lookup logic must derive its correlation key from that binding and must return
`ProviderReconciliationEvidence` bound to the exact canonical binding digest.

The application adapter re-validates:

- execution id;
- decision id;
- intent digest;
- dispatch timestamp / attempt start timestamp;
- provider evidence binding digest;
- evidence observation time relative to dispatch.

Mismatch fails closed and no generic resolution is recorded.

### 4. Provider evidence is recorded before generic resolution

Provider-specific evidence is first appended to the provider sidecar. Only then is it adapted to the
existing generic `ReconciliationEvidence` contract and passed through
`DecisionLockService.reconcile_execution`.

The provider adapter cannot directly assert `CONFLICT`. Conflict promotion remains owned by the
existing core resolution store when two opposite confirmed outcomes are observed.

The original `UNKNOWN` execution row is immutable. Reconciliation appends a resolution; it does not
rewrite history to pretend the original dispatch was known at completion time.

### 5. Confirmed outcomes require provider-verified evidence

The frozen domain model already rejects `confirmed_succeeded` and `confirmed_failed` unless the trust
level is `provider_verified`. Phase 6D preserves that requirement end to end.

Transport failure, HTTP failure, malformed JSON-RPC, missing structured status, unknown provider state,
or unavailable status service produce `still_unknown`, never a confirmed outcome.

DecisionLock-signed observations may explain why reconciliation remains unknown but cannot upgrade an
ambiguous external effect into provider truth.

### 6. First concrete provider profile: read-only MCP status tool

The first provider-specific adapter supports a configured MCP `tools/call` status operation on the
same fixed provider endpoint.

The trusted provider profile must guarantee that one configured lookup argument identifies the
original provider request by its JSON-RPC request id. DecisionLock protected MCP HTTP dispatch uses the
durable `execution_id` as that request id, allowing reconciliation without storing a raw provider
response or provider-generated operation identifier.

The status response must be a correlated JSON-RPC object with structured content. Provider status
values are explicitly mapped to succeeded, failed, or pending/unknown sets. A provider-generated
operation id, when present, is immediately hashed and only its digest is retained.

A successful, directly correlated response from the exact fixed provider endpoint is classified as
`provider_verified` within this configured status-tool contract. This is not a universal claim that
arbitrary MCP servers provide trustworthy reconciliation semantics; the status tool and its lookup
semantics are trusted provider configuration.

### 7. Reconciliation is operator-triggered in Phase 6D

Phase 6D includes a one-shot reconciliation CLI. It loads the durable external-effect binding, verifies
that the supplied upstream URL hashes to the bound provider endpoint, invokes the configured status
tool, records provider evidence, and appends the generic resolution/audit evidence.

Continuous workers, leases, scheduling, remote service coordination, and multi-process ownership are
Phase 6E concerns.

## Security invariants

- No provider side effect is dispatched through the Phase 6D-enabled MCP HTTP path before its exact
  external-effect binding is durable.
- Provider evidence cannot resolve an execution unless its binding digest matches that exact binding.
- Confirmation requires `provider_verified` evidence.
- The provider-specific adapter cannot synthesize core `CONFLICT`; conflict is derived by the durable
  core resolution history.
- Reconciliation never blindly retries the original external action.
- No raw provider response, provider secret, or credential is persisted in the provider sidecar.
- Provider operation identifiers are digest-only durable evidence.
- The configured reconciliation endpoint must match the provider endpoint digest recorded before
  dispatch.
- Evidence observed before the recorded dispatch attempt is rejected.

## Deliberate limitations

### Provider coverage

The first concrete adapter is an explicit MCP status-tool profile. It does not claim generic
reconciliation support for every MCP server, SaaS API, cloud provider, payment processor, or database.
Additional provider adapters must preserve the same frozen binding and trust invariants.

### Status-endpoint authentication

The first status-tool adapter is credentialless. Providers that require authenticated reconciliation
need a separately governed read-only reconciliation credential authority or provider-specific token
adapter. Reusing an action credential implicitly would blur authority boundaries and is not done in
this phase.

### Webhooks

Verified provider webhooks are not implemented in this phase. A future webhook adapter may produce the
same `ProviderReconciliationEvidence`, but must verify provider authenticity and exact effect binding
before claiming `provider_verified`.

### Automatic retry

Phase 6D does not add automatic retry after either `still_unknown` or confirmed failure. Retry requires
an explicit later-attempt contract and must obey the frozen idempotency/replay disposition.

### Multi-process reconciliation workers

The sidecar is durable, but distributed work claiming, worker leases, remote deployment, and service
coordination remain Phase 6E.

## Consequences

DecisionLock can now preserve an exact provider-effect identity before dispatch and later reconcile an
ambiguous MCP HTTP action with durable, provider-bound evidence without mutating the original execution
history or pretending transport correlation is provider truth.

The design remains deliberately conservative: unsupported or malformed provider evidence stays
unknown, universal provider coverage is not claimed, and any future automatic replay must be designed
on top of the frozen attempt/idempotency contract rather than inferred from a successful status query.
