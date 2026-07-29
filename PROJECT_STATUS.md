# Project status

AgentGuard v0.2.0rc1 is a local release candidate for decision-bound agent actions. It is not a
production-ready identity, credential, or distributed authorization service.

## Demonstrated locally

- strict Policy v2 and ActionIntent validation
- deterministic default-deny authorization
- provenance-aware high-impact escalation
- blast-radius limits
- signed decision and approval receipts
- credential audience/scope/TTL/tenant ceilings
- argument, principal, subject, action, resource, effects and schema binding
- atomic single-use nonce consumption
- hash-chained audit records
- MCP stdio enforcement processor
- preserved real v0.1 MCP stdio relay, inventory freshness, exact approvals, redaction,
  backpressure, bounded shutdown, audit verification, doctor, scan, and report workflows
- HTTP transport security validation primitives
- verifiable evidence bundles
- no-secret mock broker and Loadout integration contract preview

## Not demonstrated

- live Loadout API connectivity
- distributed nonce state across replicas
- production Streamable HTTP proxying and backpressure
- external audit anchoring
- independent security review
- public CI execution for this RC branch
- external validation of the pinned real MCP filesystem smoke on every supported runtime
- a production workload pilot
