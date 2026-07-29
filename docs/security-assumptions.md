# Security assumptions

- Trusted adapters, not the language model, assign verified workload identity and provenance.
- High-impact effect projections are deterministic and derived from a reviewed tool schema.
- Signing keys and broker credentials remain outside model-visible state.
- A credential broker protects raw secrets, but AgentGuard independently verifies the returned grant ceiling.
- SQLite is deployed as a local single-node state store. A replicated deployment must replace the nonce repository.
- System clocks are synchronized sufficiently for short-lived receipt verification.
