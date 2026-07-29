# Security assumptions

- Trusted adapters, not the language model, assign verified workload identity and provenance.
- High-impact effect projections are deterministic and derived from a reviewed tool schema.
- Signing keys and broker credentials remain outside model-visible state.
- A credential broker protects raw secrets. AgentGuard independently verifies both a trusted
  broker attestation and the returned grant ceiling.
- SQLite is deployed as a local single-node state store. A replicated deployment must replace the nonce repository.
- System clocks are synchronized sufficiently for short-lived receipt verification.
- Execution callers supply the currently trusted policy document. A missing or changed policy
  requires a new decision receipt; AgentGuard never silently re-authorizes during execution.
- A failed single-use issuance claim is terminal. Operators must obtain a new decision receipt
  after diagnosing broker failure; they must not delete issuance state to force a retry.
