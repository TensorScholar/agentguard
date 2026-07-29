# AgentGuard

**Provider-neutral action authorization and execution integrity for AI agents.**

> Authorize the action. Bind the credential. Verify the execution.

AgentGuard converts an agent's proposed tool action into a short-lived signed decision receipt, constrains any brokered credential to least privilege, verifies that the final execution still matches the original decision, and emits a correlated tamper-evident audit trail.

## Why this exists

Agent identity, credential storage, and tool policy are often implemented as separate controls. The dangerous gap is between them: an action can be authorized, then executed with changed arguments, a broader credential, a different tenant, or a replayed permit. AgentGuard focuses on that gap.

## Core invariant

```text
Authorized action == Credentialed action == Executed action
```

## What is implemented in v0.2.0rc1

- Strict versioned `ActionIntent`, policy, receipt, credential, execution, and audit schemas.
- Policy v2 with default deny, deterministic deny precedence, provenance conditions, tenant binding, and blast-radius budgets.
- Ed25519-signed, short-lived, request-bound decision receipts.
- Argument, principal, subject, action, resource, tool-schema, policy and projected-effects digests.
- Atomic one-use nonce consumption in SQLite.
- Provider-neutral credential broker port and a no-secret mock Loadout-style broker.
- Scope, TTL, audience, tenant and decision binding checks for credential grants.
- MCP stdio message processor with fail-closed `tools/call` handling and bounded messages.
- HTTP transport security helpers for Origin, Host, and mirrored-header/body validation.
- Hash-chained local audit events and verifiable evidence bundles.
- Meeting-ready demo covering a valid scoped refund, argument mutation, scope inflation and replay.

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e .

agentguard init
agentguard demo --output .agentguard/demo
cat .agentguard/demo/results.json
agentguard evidence-verify .agentguard/demo/evidence
```

## Manual flow

```bash
agentguard authorize   --request examples/scoped-refund/request.json   --policy examples/scoped-refund/policy.yaml   --output decision.json

agentguard broker-demo decision.json --output grant.json

agentguard verify-execution   --request examples/scoped-refund/request.json   --receipt decision.json   --grant grant.json
```

## Product boundary

AgentGuard owns action normalization, deterministic authorization, blast-radius limits, signed decision receipts, credential ceilings, execution-time binding, approval artifacts and evidence correlation.

AgentGuard does **not** own model evaluation, prompt-injection classification, identity issuance, credential vaulting, secret storage, agent orchestration, SIEM storage or a hosted dashboard.

## Loadout integration status

The repository includes a broker-neutral contract, mock adapter, schemas, threat model and integration RFC. It does not claim a live Loadout API integration because no reviewed API contract or sandbox was available during this release build.

## Release status

**Production-grade release candidate, not production-ready.** Public CI, external security review, a real broker sandbox integration and an external pilot remain required before a stable `v0.2.0` release.
