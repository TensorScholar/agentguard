# Project status

AgentGuard v0.2.0rc1 is a local release candidate for decision-bound agent actions. It is not a
production-ready identity, credential, or distributed authorization service.

## Demonstrated locally

- strict Policy v2 and ActionIntent validation
- deterministic default-deny authorization
- provenance-aware high-impact escalation
- blast-radius limits
- verified signed decision and approval receipts with complete ActionIntent binding
- authenticated broker grants plus credential audience/scope/TTL/tenant ceilings
- atomic single-use credential issuance, approval-use, and execution-nonce consumption
- execution-time current-policy digest verification and delegation capability ceilings
- fresh MCP tool-schema resolution with unavailable/stale/changed fail-closed handling
- hash-chained audit records
- MCP stdio enforcement processor
- preserved real v0.1 MCP stdio relay, inventory freshness, exact approvals, redaction,
  backpressure, bounded shutdown, audit verification, doctor, scan, and report workflows
- HTTP transport security validation primitives
- closed-world verifiable evidence bundles that reject unlisted files
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
