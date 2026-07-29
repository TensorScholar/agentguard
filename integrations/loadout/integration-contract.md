# AgentGuard ↔ Loadout contract preview

## AgentGuard to broker

- signed decision receipt or a verified projection of it
- `trace_id`, `decision_id`, workload/tenant identity digest
- audience, exact scope set and maximum TTL
- single-use requirement and optional approval identifier

## Broker to AgentGuard/executor

- stable `issuance_id`
- opaque handle or brokered-execution mode
- audience, exact issued scopes, tenant and issued/expiry timestamps
- broker identity, key identifier and a cryptographic attestation over the complete grant context
- digest of the opaque handle, without placing the raw handle in evidence
- no raw secret in model-visible fields

## Rejection rules

- grant scopes are not a subset of the decision ceiling
- TTL exceeds the ceiling
- audience, tenant, decision or trace binding differs
- receipt is expired, replayed, revoked or invalid
- approval evidence is absent for an approval-required decision
- broker identity/key is unknown or the grant attestation is missing, malformed or invalid

This is a provider-neutral contract. Field names and authentication details must be reconciled with Loadout's reviewed API before a live adapter is implemented.
