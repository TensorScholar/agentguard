# Product boundary

AgentGuard is the action-integrity layer between an agent runtime and a tool executor.

It owns action normalization, deterministic policy, authority ceilings, signed receipts, execution binding, replay prevention and correlated evidence.

It integrates with, but does not replace:

- workload identity systems such as OIDC or SPIFFE
- credential brokers and vaults such as Loadout or Vault
- agent frameworks and model providers
- evaluation systems such as ProofDiff
- policy-change regression tools such as PermitDiff
- SIEM and telemetry backends
