# Market-gap analysis

## Product position

AgentGuard is not another prompt filter, LLM evaluator or observability dashboard. Its narrow product
contract is **action integrity**: deterministic proof that the action authorized, the authority issued
and the action executed remain bound to the same request.

## Gaps addressed by RC2

### 1. Authorization-to-execution drift

Many systems make an authorization decision before credentials are issued or before the final tool
call is assembled. AgentGuard signs the complete action intent, constrains credentials to the same
boundary and revalidates at execution time.

### 2. Gateway bypass blindness

A security proxy is ineffective when a client retains another direct MCP entry for the same server.
`mcp-posture` inventories protected, direct, ambiguous and invalid routes and identifies matching
protected-plus-direct downstream fingerprints. This creates a CI-enforceable coverage control rather
than assuming proxy installation equals enforcement.

### 3. Self-referential audit integrity

A local hash chain can detect modification of retained events but not complete truncation or database
replacement. Signed checkpoints make a ledger prefix externally anchorable without requiring a hosted
control plane.

### 4. Evidence authenticity

Checksums prove internal consistency, not who produced a bundle. Optional Ed25519 manifest
attestations let an auditor require a trusted signer while preserving offline verification.

### 5. Approval inflation

Approval artifacts are often treated as broad exceptions. RC2 binds approvals to the decision,
action, resource, arguments, budget, validity window and maximum use count.

### 6. Credential authority inflation

Credential grants are authenticated and cannot exceed the decision's audience, scopes, tenant, TTL or
absolute validity window. Brokered execution mode cannot leak an opaque credential handle to the agent.

### 7. Compatibility without silent downgrade

The project preserves useful v0.1 scanner and MCP workflows, but hardens inventory races, server
identity, secret persistence, path/host normalization and explicit audit migration. Compatibility is
kept visible rather than silently mixing v1 and v2 state semantics.

## Deliberate non-features

- No probabilistic “AI safety score” in the enforcement path.
- No claim that prompt-injection classification can replace least privilege.
- No hosted dashboard required for local authorization.
- No embedded secret vault.
- No universal claim that all agent execution is intercepted.

These exclusions keep the trusted computing base small and the primary controls deterministic.

## Commercial wedge

The strongest initial use case is a security/platform team adopting MCP and internal agents that needs:

- a developer-local and CI-enforceable gateway;
- exact approval and credential boundaries;
- auditable evidence without sending action data to a third party;
- proof that configurations do not retain an obvious direct bypass;
- a migration path toward broker, SIEM and distributed state integrations.
