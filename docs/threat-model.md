# Threat model

## Protected properties

- An execution must not exceed the authority represented by the signed decision receipt.
- A credential grant must not exceed the receipt's audience, scope, TTL or tenant ceiling.
- A receipt and approval must not be replayed beyond their allowed use count.
- Raw credentials must not enter model context, audit logs or evidence bundles.

## Primary threats

Argument substitution, action substitution, delegation escalation, confused deputy, cross-tenant
reuse, receipt replay, credential scope inflation, changed-policy execution, stale tool schema,
provenance spoofing, approval substitution, audit tampering, audit truncation, DNS rebinding,
header/body confusion and broker outage bypass.

## Trust assumptions

- The protocol adapter is trusted to label provenance and verified identity accurately.
- The private signing key remains outside the model process and is filesystem-protected.
- SQLite single-node transactions are sufficient only for one local enforcement node.
- The mock broker never represents a real credential system.

## Explicit limitations

Hash chaining detects modification of retained events but does not alone prove that the tail was not truncated. Export the audit head to an external location for truncation detection. Multi-replica nonce consumption requires a transactional shared store and is outside the single-node RC boundary.
