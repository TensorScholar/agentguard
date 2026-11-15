# Credential Contract

This is the mechanism this release line leads with, written out precisely. If you take one thing away
from this repository, take this: **an agent should never hold a secret broader than the action it is
currently authorized to perform, and the evidence should prove which secret and which action.**

No new provider is added here. This documents what the code already does.

---

## The four-step contract

### 1. The decision issues a ceiling

Policy v2 evaluation produces a `credential_ceiling` — a `CredentialProfile` carrying `audience`,
`scopes`, `tenant_id`, and `maximum_ttl_seconds` — which is embedded in the Ed25519-signed
`DecisionReceipt` (`engine/receipts.py:69-107`). The ceiling is **derived from the signed decision**,
not from the caller's request. A caller cannot ask for a wider ceiling; there is no code path that
lets one.

If a rule matches with `ALLOW` or `REQUIRE_APPROVAL` and declares a `credential` block, the ceiling is
attached. A `DENY` decision carries none.

### 2. A credential request is validated against the ceiling, not against the caller

`validate_credential_request` (`engine/credentials.py:16-35`) enforces, in order:

| Check | Failure code |
|---|---|
| Approval satisfied, if the decision required one | `credential.approval_required` |
| Decision effect is `ALLOW` or `REQUIRE_APPROVAL` | `credential.decision_not_allow` |
| A ceiling exists | `credential.no_ceiling` |
| Request binds to *this* decision and trace | `credential.decision_binding_mismatch` |
| Audience equals the ceiling audience | `credential.audience_mismatch` |
| Requested scopes are a **subset** of the ceiling | `credential.requested_scope_exceeds_decision` |
| Requested TTL ≤ ceiling `maximum_ttl_seconds` | `credential.requested_ttl_exceeds_decision` |
| Tenant matches, when the ceiling pins one | `credential.tenant_mismatch` |

Then the authority matches a durable `CredentialAuthorityProfile` by `(audience, tenant_id)`. If the
requested scopes are not **exactly equal** to the profile's scopes, issuance fails with
`credential.profile_scope_mismatch`.

That equality is deliberate and is the honest part of this design:

> `adapters/broker/production.py:250-252` — *"A static/external secret is not attenuated merely because
> a caller asks for fewer scopes. Exact equality prevents DecisionLock from claiming least privilege it
> cannot technically enforce at the provider."*

Because the underlying secret is a single environment variable, DecisionLock **cannot** attenuate it.
Rather than claim least-privilege it cannot enforce, it refuses to grant unless the requested scope is
exactly what the profile declares. If you want a narrower credential, you must configure a narrower
secret. That is a real limit, stated in the code rather than papered over.

### 3. The grant carries a binding digest, never a secret

The issued `CredentialGrant` in `brokered_execution` mode contains:

- a `credential_handle_digest` — a SHA-256 digest of the *source binding* (e.g. which environment
  variable), not of the secret and not the secret;
- audience, scopes, tenant, and an `expires_at` clamped to
  `min(now + requested_ttl, receipt.expires_at, profile.expires_at)` — the grant can never outlive the
  decision that authorized it;
- an Ed25519 attestation over grant metadata only (`credential_grant_attestation_payload`,
  `engine/credentials.py:38-54`, which is documented to "never include the opaque handle").

`verify_credential_grant` (`engine/credentials.py:66-98`) rejects a `brokered_execution` grant that
carries any `credential_handle` at all (`credential.handle_forbidden`) — a grant must never be able to
hold the secret.

At execution time `validate_execution_authority` requires a grant **iff** the receipt has a ceiling
(`execution.py:241-248`): a ceiling with no grant fails `execution.credential_missing`, and a grant with
no ceiling fails `execution.credential_unexpected`. There is no "optional credential" path.

### 4. The secret is resolved at the last moment

`BrokeredCredentialAuthority.resolve` is called during dispatch, not at issuance. It re-checks broker
and key binding, rejects an expired authority (`credential.expired`), matches the provider identity,
and only then reads the source. The resolved material becomes a single request header, built as
`{header_scheme} {secret}` (`production.py:322-331`), which is validated to contain no `\r`, `\n`, or
NUL and no leading/trailing whitespace before use.

Header injection is constrained too: `CredentialAuthorityProfile.header_name` is validated against the
HTTP token grammar and **forbidden** if it is a hop-by-hop header, a request framing header, or any
name starting with `mcp-param-` (`domain/credential_authority.py:14-35, 57-64`). An operator cannot
configure the gateway to rewrite `Host`, `Content-Length`, `Transfer-Encoding`, or an MCP parameter
header with a secret.

### Where the secret never goes

| Artifact | Contains the secret? |
|---|---|
| `DecisionReceipt` | No — a `credential_ceiling` (policy metadata) only |
| `CredentialGrant` | No — a `credential_handle_digest` over the source binding |
| Durable SQLite state | No |
| Audit ledger | No — secret minimization at the persistence boundary |
| Evidence bundle / attestation | No |
| Process memory | Yes, transiently. **Not zeroized.** Python cannot guarantee erasure of immutable `str` bytes; see ADR 0005 and `docs/limitations.md`. |

---

## The documented happy path: `decisionlock-mcp-http`

The production credential authority is reachable from the Streamable HTTP gateway. It is the only
supported path that both resolves secrets late *and* executes through a protected proxy.

`decisionlock init` writes the signing key the gateway expects, so no manual key generation is needed:

```bash
export PAYMENTS_API_TOKEN='...'          # the secret; never written to disk by DecisionLock

decisionlock-mcp-http \
  --policy examples/harness/policy.yaml \
  --key .decisionlock/demo/private.pem \
  --server-id customer-operations \
  --upstream-url https://payments.internal/mcp \
  --tenant-id acme \
  --credential-env PAYMENTS_API_TOKEN \
  --credential-audience payments \
  --credential-scope refund:create \
  --credential-header-name Authorization \
  --credential-header-scheme Bearer \
  --access-token-env DECISIONLOCK_HTTP_ACCESS_TOKEN \
  --provenance authenticated_user_input \
  --provenance-verified
```

This constructs an `EnvironmentCredentialSource`, stores a durable non-secret
`CredentialAuthorityProfile` keyed to that source binding, and builds a `BrokeredCredentialAuthority`
whose grant verifier is wired into the protected service (`http_cli.py:138-172`).

### `--provenance` is required for the live path

Every protected MCP adapter derives the intent from the wire and cannot know where the call came
from, so provenance is **deployment configuration**, supplied by the operator:

| Flag | Meaning |
|---|---|
| `--provenance <label>` | Repeatable. Provenance the transport establishes. Omitted ⇒ `unverified`. |
| `--provenance-verified` | Assert that the declared provenance has been cryptographically verified. |

Without it, every intent is `(unverified, False)` and any policy with
`unknown_provenance != allow` will refuse every call. `unverified` cannot be combined with a
trusted label — the parser rejects that as contradictory rather than silently picking one.

This is the adapter-as-TCB-boundary assumption from [the threat model](threat-model.md): the
deployment is trusted to label provenance accurately. The default is deliberately the safe value.

Requires the `http` extra. A non-loopback listener additionally requires TLS, a bearer token, and an
explicit Host allowlist; browser-reachable use additionally requires an Origin allowlist
(`service_deployment.py`). Those are enforced, not advisory.

### Credential failure codes

The gateway reports the specific stable code in `error.data.reason_code`, so a misconfiguration is
identifiable without reading source:

```json
{"error": {"code": -32003, "message": "credential issuance failed",
           "data": {"reason": "CredentialAuthorityError",
                    "reason_code": "credential.profile_scope_mismatch"}}}
```

| Code | Usual cause |
|---|---|
| `credential.profile_unavailable` | No stored profile for `(audience, tenant_id)`. Usually `--tenant-id` does not match the policy ceiling's `tenant_id`. |
| `credential.profile_scope_mismatch` | `--credential-scope` differs from the policy ceiling's scopes. Exact equality is required — see above. |
| `credential.tenant_mismatch` / `credential.audience_mismatch` | Ceiling and request disagree. |
| `credential.requested_ttl_exceeds_decision` | Requested TTL above the ceiling. |
| `credential.source_binding_mismatch` | Profile was stored against a different credential source. |
| `credential.profile_expired` / `credential.grant_window_invalid` | The decision or profile expired before issuance. |
| `credential.material_invalid` | The resolved secret was empty, whitespace-padded, or contained CR/LF/NUL. |
| `credential.handle_forbidden` | A `brokered_execution` grant carried secret material. |

A **missing** `--credential-key` file is caught at startup with an actionable message naming
`decisionlock init`.

---

## The mock broker is not production

`decisionlock broker-demo` uses `adapters/broker/mock.py`. It exists to exercise grant signing and
ceiling enforcement **without a secret source**, in demos and contract tests.

> `docs/limitations.md` — *"The preserved mock broker is for demos/contract testing and must not be
> represented as a production credential provider."*

The mock broker ships inside the wheel because the test suite uses it. That is a packaging
inconvenience, not an endorsement.

---

## What is still missing

Stated as known limits, not hidden gaps:

| Missing | Consequence | Phase |
|---|---|---|
| **Audience proof** | DecisionLock binds a *declared* audience to a decision; it does not cryptographically prove the provider will accept that audience for that token. A misconfigured profile can claim an audience the provider does not enforce. | 2 |
| **Native downscoping / token minting** | No provider-native short-lived or audience-restricted token minting. To narrow a credential you must configure a narrower secret, because a single env var cannot be attenuated. | 2 |
| **Vault / KMS / HSM integration** | The source is one environment variable. No rotation, no hardware key custody, no short-lived secret issuance. | 2 |
| **Revocation semantics** | Profile revocation is durable state, but there is no upstream revocation call — a leaked secret stays valid at the provider until it expires. | 2 |
| **Memory zeroization** | Secrets are not scrubbed from process memory. | not planned (ADR 0005) |
| **Multiple credential sources per decision** | One ceiling, one source binding. A request needing two providers' credentials is out of scope. | not planned |
| **Fuzzing of the credential parser** | The credential and policy parsers have no property-based test campaign. | Phase 2 debt |

---

## Verify it yourself

```bash
# Grant signing and ceiling enforcement without a secret source (mock, contract test only)
decisionlock broker-demo examples/scoped-refund/request.json decision.json --output grant.json

# Preflight the grant against the decision — ceiling, audience, tenant, TTL.
# Does NOT execute and does NOT consume the nonce.
decisionlock verify-execution examples/scoped-refund/request.json decision.json \
  examples/scoped-refund/policy.yaml --grant grant.json

# Confirm no secret reached the evidence bundle
decisionlock evidence-verify evidence/ --public-key .decisionlock/demo/public.pem --require-signature
grep -R "$PAYMENTS_API_TOKEN" evidence/ && echo "LEAK" || echo "no secret in bundle"
```

Related: [Scenarios](scenarios.md) · [Limitations](limitations.md) · [Threat Model](threat-model.md) ·
[ADR 0005](adr/0005-production-credential-authority.md)
