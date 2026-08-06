# Threat Model

## Protected properties

- Execution must not exceed the authority represented by the signed decision receipt.
- Approval must not expand the original execution budget or validity window.
- Credential grants must remain inside the receipt's audience, scope, tenant, and lifetime ceiling.
- Receipts and approvals must not be replayed beyond their permitted use count.
- MCP calls must fail closed when the current tool inventory or schema cannot be trusted.
- Raw credentials and common secret values must not enter retained audit or evidence artifacts.
- A protected MCP configuration must not silently retain a parallel direct route.
- Audit truncation or replacement must be detectable when a signed checkpoint is stored externally.
- Evidence authenticity must be verifiable when a trusted public key is supplied.

## Primary threats

Argument substitution, action substitution, confused-deputy behavior, cross-tenant reuse, receipt replay, credential inflation, stale or poisoned tool inventory, provenance spoofing, approval substitution, budget expansion, audit modification, audit truncation, evidence replacement, DNS and host-normalization bypass, metadata-service SSRF, path-encoding bypass, symlink races, stdout-backpressure denial of service, direct-route gateway bypass, and broker-outage bypass.

## Trust boundaries

1. **Agent or model process:** untrusted proposal source.
2. **Protocol adapter:** trusted to parse the protocol, derive provenance, and route calls through authorization.
3. **Action-integrity kernel:** trusted deterministic policy, receipt, and execution checks.
4. **Signer:** trusted private-key boundary; should be separated from the model process in production.
5. **Credential broker and executor:** trusted to issue and use credentials only within signed ceilings.
6. **State store:** trusted for atomic local replay and use-count enforcement.
7. **Checkpoint store:** independently controlled storage required to detect complete ledger loss.
8. **Operating system and network:** outside AgentGuard's control; must enforce file, process, and egress isolation.

## Explicit assumptions

- The protocol adapter labels verified identity and provenance accurately.
- The final executor invokes the exact action that AgentGuard verified.
- Private signing material is inaccessible to the model and untrusted tools.
- SQLite is used by one enforcement node; distributed replicas require shared transactional state.
- `mcp-posture` sees every configuration file that the operator asks it to inspect.
- A signed checkpoint is exported to a location an attacker controlling the ledger cannot rewrite.
- Public keys used to verify evidence or checkpoints are distributed through a trusted channel.

## Residual risk

A local library cannot prove that an application did not invoke a second, uninstrumented executor. A configuration scanner cannot discover an undisclosed route, dynamically constructed transport, or network path outside the supplied files. Hash chains without external checkpoints cannot prove tail completeness. File-level hardening does not replace process sandboxing, kernel controls, or secret-manager policy.
