# RFC: AgentGuard and Aident Loadout integration

## Goal

Connect AgentGuard's authorization decision to Loadout's scoped credential issuance without exposing raw credentials to the model, then correlate authorization, issuance and execution in one timeline.

## Proposed contract

1. AgentGuard receives a canonical action intent and emits a signed `DecisionReceipt`.
2. Only an `allow` receipt may produce a `CredentialRequest`.
3. Loadout validates the receipt or receives an attested subset of its fields.
4. Loadout returns an opaque handle or performs brokered execution.
5. AgentGuard rejects any grant whose audience, scopes, TTL or tenant exceed the receipt.
6. The executor revalidates receipt, grant, arguments, schema and nonce immediately before execution.
7. Both systems emit events using `trace_id`, `decision_id` and `issuance_id`.

## Questions for Loadout

- Does Loadout return an opaque handle, inject a token at an executor boundary, or proxy the action?
- What workload identity and authentication mechanism protects issuance?
- Can AgentGuard provide a custom correlation ID and signed receipt?
- Are audience, scope, tenant, TTL and single-use semantics requestable?
- What are the revocation, retry and audit export contracts?
- Is a sandbox tenant available for a joint integration spike?

## Non-claim

`LoadoutPreviewBroker` intentionally performs no network call. A real adapter must be built only after API and sandbox review.
