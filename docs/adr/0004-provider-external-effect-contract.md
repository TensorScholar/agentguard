# ADR 0004: Provider and External-Effect Contract

Status: Accepted for Phase 6 contract freeze

Date: 2026-09-01

## Context

Phase 5 established durable authorization and one-winner protected execution semantics. Phase 6A/6B added the protected modern MCP/HTTP transport boundary. The next phases introduce production credential authority (6C) and provider-specific durable reconciliation (6D).

Those phases must not independently invent provider identity, external-operation identity, credential binding, retry semantics, or evidence semantics. If they do, a credential can be valid in isolation while being used against the wrong provider/account/operation, or reconciliation evidence can be correlated to the wrong dispatch attempt.

## Decision

AgentGuard freezes a provider-neutral external-effect contract before implementing 6C or 6D.

The contract is represented by immutable strict domain value objects and canonical SHA-256 digests.

### Provider identity

`ProviderIdentity` identifies the external authority capable of realizing an effect. It requires a provider id and at least one concrete provider scope: an account identity or a bound endpoint digest. AgentGuard tenant identity may additionally be carried, but is not sufficient by itself to identify an external provider authority.

### External operation identity

`ExternalOperationIdentity` is an AgentGuard-stable logical operation id plus operation kind and operation name. It is assigned independently of any provider-generated request/operation id so it exists before dispatch and remains stable across evidence collection.

### Credential binding

`CredentialBinding` contains authenticated non-secret credential metadata only: grant/issuance identity, credential-handle digest, audience, scopes, tenant, broker, and broker key identity. Raw credentials and opaque handles are forbidden from this contract.

6C must project credentials into this binding only after existing credential verification has succeeded.

### Execution attempt identity

`ExecutionAttemptIdentity` makes retries explicit. The first attempt has no parent. Every later attempt must identify its parent attempt. An attempt cannot parent itself.

A retry is therefore a new attempt under the same logical execution, never an unrecorded repeat of a previous dispatch.

### Idempotency and replay

`IdempotencyBinding` separates idempotency mechanism from replay disposition.

Supported mechanisms at contract-freeze time are:

- `none`
- `caller_supplied_key`
- `agentguard_generated_key`

Replay dispositions are:

- `forbidden`
- `reconcile_before_retry`
- `same_idempotency_key_only`

A key-based mechanism requires a key digest. The contract never persists the raw idempotency key. `same_idempotency_key_only` is invalid without a key mechanism. A retry attempt is invalid when replay is forbidden.

The default for a provider with no proven idempotency mechanism is `reconcile_before_retry`, not blind retry.

### External-effect binding

`ExternalEffectBinding` binds one authorized effect to:

- decision and intent digest;
- action, resource, and argument digests;
- provider identity;
- logical external operation identity;
- optional verified credential binding;
- execution attempt identity;
- idempotency/replay semantics.

Its canonical digest is the correlation key for provider evidence.

Changing a security-relevant component changes the binding digest.

### Provider evidence

`ProviderEvidence` contains digest-only evidence metadata and MUST reference the exact `ExternalEffectBinding` digest. Provider response bodies, raw credentials, and provider secrets are outside the contract.

`ProviderReconciliationEvidence` adds a reconciliation conclusion. `confirmed_succeeded` and `confirmed_failed` require `provider_verified` evidence. AgentGuard-signed or merely correlated evidence cannot upgrade an ambiguous execution to a confirmed outcome.

The pre-existing generic `ReconciliationEvidence` remains compatibility infrastructure. Phase 6D should adapt provider-specific evidence into the frozen provider-effect contract before resolving durable execution state.

## Security invariants

1. Provider/account/endpoint identity is explicit before dispatch.
2. Credential authority is non-secret and cryptographically referential; raw secret material is not part of durable provider-effect identity.
3. Every retry is a distinct, lineage-bound attempt.
4. Absence of proven idempotency never implies retry safety.
5. Provider evidence is useless for state resolution unless it binds to the exact external-effect digest.
6. Confirmed external outcomes require provider-verified evidence.
7. Provider-generated operation identifiers are evidence/correlation data, not substitutes for AgentGuard's pre-dispatch logical operation identity.
8. Contract digests use AgentGuard canonicalization and are deterministic across set ordering.

## Non-goals

This ADR does not implement:

- production secret acquisition, rotation, revocation, or vault integration (6C);
- provider-specific status APIs, webhook verification, or durable reconciliation workers (6D);
- database schema changes for provider-specific evidence (6D);
- remote/multi-process deployment (6E);
- blind automatic retries;
- a provider-specific SDK contract.

## Consequences

6C and 6D can proceed independently at implementation level while sharing one security vocabulary. Provider adapters may add provider-specific evidence, but they may not weaken the frozen identity, binding, trust, or replay invariants without a new ADR and explicit migration.
