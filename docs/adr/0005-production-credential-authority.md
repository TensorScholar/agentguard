# ADR 0005: Production Credential Authority

- Status: Accepted for Phase 6C
- Date: 2026-09-01
- Depends on: ADR 0004 provider/external-effect contract freeze

## Context

AgentGuard policy can already constrain credential audience, scopes, tenant, TTL, and single-use
issuance. Phase 5 also authenticates credential grants and binds verified credential metadata into
protected execution authority. The missing production boundary was the provider secret itself:
protected MCP HTTP execution could not turn verified authority into provider authentication without
placing secret-bearing material in caller-visible grants or durable execution state.

Phase 6C introduces a production credential authority for that boundary. It is intentionally
provider-neutral. Provider-specific token minting, reconciliation, and service deployment remain
separate phases.

## Decision

### 1. Durable state is non-secret

A `CredentialAuthorityProfile` persists only:

- a stable profile identifier;
- exact `ProviderIdentity`;
- policy audience, scopes, and tenant binding;
- a digest identifying the configured secret source;
- the outbound credential header format;
- optional profile expiry;
- active/revoked lifecycle state and revocation metadata.

The provider credential value is not stored in the profile database, execution database, audit
ledger, `CredentialGrant`, or `VerifiedExecution`.

### 2. Grants authenticate a profile binding, not a secret

The production authority issues signed `brokered_execution` grants. Their
`credential_handle_digest` is the canonical digest of the credential profile. `credential_handle`
is absent.

The existing broker signature, receipt binding, audience, scope, tenant, TTL, and authorization
window verification remains mandatory.

### 3. Provider identity is exact and immutable for the dispatch

The profile binds the shared `ProviderIdentity` contract from ADR 0004. The modern MCP HTTP resource
also binds `provider_identity_digest`. The protected executor validates that digest before dispatch,
and the credential resolver independently requires exact provider identity equality before reading
secret material.

Endpoint or provider substitution therefore fails before the secret source is read.

### 4. Static/external secrets do not imply fake attenuation

For an environment-backed or otherwise static provider credential, AgentGuard cannot prove that a
request for a subset of scopes has produced a provider credential with fewer privileges. Therefore
production issuance requires the requested scope set to equal the configured profile scope set.

A future provider adapter may support real provider-side scoped token minting. Only such an adapter
may safely claim scope attenuation.

### 5. Resolution occurs at final protected dispatch

The provider secret source is read only after:

1. request/header validation;
2. fresh tool-schema discovery;
3. policy authorization;
4. credential issuance and signature verification;
5. protected execution reservation;
6. final provider/resource binding validation.

The resolver re-checks grant expiry, profile activity/revocation, profile expiry, provider identity,
audience, scopes, tenant, and source binding immediately before returning ephemeral header material.

The HTTP executor injects that material into a newly constructed outbound header map immediately
before the upstream `send` call. Raw inbound client authorization headers are never reused for the
protected provider call.

### 6. Revocation is durable and checked after issuance

Credential profiles have durable active/revoked state. Revoking a profile invalidates already-issued
brokered grants at resolution time. Revocation is checked before the secret source is read and before
external dispatch.

A revoked profile is never silently reactivated by storing another profile with the same identifier.

### 7. Secret rotation does not require grant reissue when source identity is stable

The durable profile binds a secret-source identity digest rather than a secret-value digest. A source
may rotate the underlying credential while preserving its identity. An already-valid grant then
resolves the new value at dispatch time, subject to all normal profile/grant checks.

Changing the source identity itself requires an explicit new profile binding and therefore changes
the authenticated profile digest.

### 8. Broker trust is separate from decision-signing trust

The production credential authority has its own Ed25519 private key and broker identity. The service
verifies credential grants through the broker grant verifier rather than implicitly trusting the
decision-signing key.

The CLI requires an existing credential-broker private key; it does not silently create one.

## Security invariants

- No provider secret is serialized into a domain model intended for durable storage.
- No provider secret is written to AgentGuard execution/audit SQLite state by the credential path.
- No provider secret is written to the credential-profile SQLite state.
- Client-supplied `Authorization` is not forwarded to the protected provider dispatch.
- Revocation and provider substitution fail before secret-source reads.
- Outbound credential header names cannot replace MCP routing, hop-by-hop, content, cookie, or
  `Mcp-Param-*` headers.
- Invalid secret material containing surrounding whitespace, CR, LF, or NUL fails closed.
- The existing one-winner execution reservation remains authoritative; credential resolution does not
  create a parallel execution lifecycle.

## Operational interface

The HTTP CLI can opt into environment-backed credential authority with an explicit credential
audience, one or more exact scopes, profile state path, broker private key, and provider identity.

Credential configuration is optional. Existing non-credential HTTP behavior remains available when
no credential authority is configured.

## Deliberate limitations

### Authenticated schema discovery

Phase 6C keeps pre-authorization `tools/list` schema discovery credentialless. This avoids a circular
trust path in which an action credential is exposed before AgentGuard has authorized the action.
An upstream that requires authentication for schema discovery therefore needs a separately governed,
read-only discovery authority; that is not implemented in this phase.

### Generic protected executors

The Phase 6C production credential resolver is integrated with the protected modern MCP HTTP
executor. Other `ProtectedExecutor` implementations do not automatically gain provider credential
resolution. They must implement an equivalent trusted dispatch-time resolver before being used for
brokered provider credentials. AgentGuard does not claim universal credential injection for arbitrary
third-party executors in Phase 6C.

### Memory zeroization

Python immutable strings cannot provide a reliable application-level guarantee that secret bytes are
zeroized from process memory. Phase 6C minimizes secret lifetime and avoids persistence/logging, but
does not claim cryptographic memory erasure. A future isolated credential sidecar or native secret
container may provide a stronger memory-handling boundary.

### Provider-minted short-lived credentials

The first production source adapter is environment-backed. It supports safe late binding, rotation,
revocation, provider binding, and non-persistence, but it does not mint provider-native short-lived
or down-scoped credentials. Provider-specific minting adapters can implement the same source/resolver
ports later without changing the frozen external-effect contracts.

## Consequences

This phase closes the production execution gap without turning AgentGuard into a credential vault or
embedding provider secrets in authorization artifacts. The tradeoff is deliberate conservatism:
static credentials are treated as having their configured real privilege, schema discovery remains
unauthenticated, and stronger process-isolation/zeroization guarantees are deferred rather than
claimed without evidence.
