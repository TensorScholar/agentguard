# Trust boundaries

- Agent/model process: untrusted for credentials and provenance assertions.
- AgentGuard protocol adapter: trusted normalization boundary.
- AgentGuard signing key: isolated secret.
- Loadout/broker: trusted to protect raw credentials but its grant is still verified against the decision ceiling.
- Tool executor: trusted to verify the receipt and inject credentials outside model context.
