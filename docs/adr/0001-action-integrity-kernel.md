# ADR 0001: Action-integrity kernel

## Status

Accepted. Temporal-hardening follow-up Q02 is **superseded and closed by Q04-01**; see
[Q02 / Q04-01](../PROGRESS_TRACKER.md). The decision below stands.

Phase 0 clarification: the compatibility entry point that validated execution authority was renamed
`authorize_execution` -> `preflight_execution` because it does not consume the decision nonce and
therefore never provided single-use enforcement. The old name is retained only as a deprecated
wrapper that emits a `DeprecationWarning`. This is a naming correction, not a change to the
invariant.

## Decision

AgentGuard will optimize for the invariant that the authorized action, credentialed action and executed action are identical within explicit ceilings. Generic guardrails, model judgment and orchestration remain outside the core.
