# ADR 0007: Service and multi-process deployment boundary

- Status: Accepted for Phase 6E validation
- Base checkpoint: `70b2c69d91c958c0d688ea6980c3adf85efb4764`
- Scope: single-host service deployment and provider reconciliation coordination

## Context

Phase 6D made provider external-effect bindings and reconciliation evidence durable, but it
intentionally did not define ownership when more than one process attempts to reconcile the same
UNKNOWN execution. Independent processes could therefore duplicate provider status work. The core
resolution ledger remained deterministic, but duplicate provider calls and stale worker commits
were not an acceptable production service boundary.

Phase 6E must add coordination without weakening the Phase 6 provider contract, introducing blind
retries, or pretending that a local SQLite deployment is a distributed consensus system.

## Decision

### 1. Reconciliation ownership is a durable lease

Each UNKNOWN execution may have at most one active reconciliation lease. A lease records:

- execution ID;
- opaque worker/operator owner ID;
- acquisition time;
- expiry time;
- a monotonically increasing fencing token.

Lease acquisition uses `BEGIN IMMEDIATE` on the same SQLite database as the core execution and
resolution ledger. Active ownership blocks another claimant. After expiry a new claimant may take
over and receives a strictly newer fencing token. All accepted aware lease timestamps are
canonicalized to UTC before persistence or comparison; lease validity never depends on lexical
ordering of differently offset ISO-8601 strings.

### 2. Authoritative resolution commits are fenced atomically

A worker does not merely check a lease before provider I/O. The current owner ID, fencing token,
and expiry are revalidated in the same SQLite transaction that writes the authoritative
`execution_resolutions` row. A worker whose lease expired or was superseded cannot commit a
resolution even if it started provider reconciliation earlier.

The fenced state implementation is fail-closed: an authoritative resolution attempt without an
active `resolution_lease(...)` scope is rejected rather than falling back to the unfenced Phase 6D
write path. The ordinary `SQLiteState` remains the generic Phase 6D implementation; callers that
select `SQLiteFencedReconciliationState` explicitly opt into mandatory ownership fencing.

Provider-specific evidence remains an append-only evidence record in the Phase 6D sidecar. A stale
worker may have already observed and persisted provider evidence before losing its lease; that
record is evidence, not authoritative execution state. Only a currently fenced resolution commit
changes the durable reconciliation history used by DecisionLock.

### 3. One-shot operator reconciliation uses the same ownership protocol

`decisionlock-reconcile` claims a lease before provider reconciliation and performs its resolution
inside the fenced scope. It therefore cannot silently race an active background worker.

### 4. Background workers are bounded and restart-safe

`decisionlock-reconcile-worker`:

- excludes automatic startup recovery to prevent taking over live dispatches (operator recovery is explicit);
- considers UNKNOWN executions and processes only those with durable external-effect bindings;
- claims work before provider lookup;
- requires the lease TTL to exceed the configured provider timeout by more than five seconds;
- bounds claimed provider reconciliation attempts per tick and bounds polling intervals;
- does not allow earlier unbound UNKNOWN records or busy leases to consume attempt capacity and starve a
  later actionable execution;
- handles SIGINT/SIGTERM with a graceful stop boundary;
- emits structured JSON operational diagnostics without raw credentials or provider response
  bodies;
- exposes an executable health check for durable-state readiness.

Lease rows survive process crashes. They are not deleted merely because a process exits. Another
process may take over only after the recorded expiry, which prevents immediate concurrent replay
after a crash.

The Phase 6D provider repository intentionally exposes point lookup rather than a binding-list work
index. Consequently, the SQLite worker may inspect more UNKNOWN rows than its claimed-attempt limit
when old unbound or terminal rows exist. This is an explicit single-host operational limitation, not a reason to
change the frozen provider contract in Phase 6E. A future indexed candidate-discovery adapter may
optimize scanning while preserving the same ownership and fencing semantics.

### 5. HTTP service remote binding is fail-closed

Loopback remains the default and requires no network exposure relaxation. A non-loopback listener
is accepted only when all of the following are configured:

1. a non-empty Bearer access token sourced from the configured environment variable;
2. an explicit Host allowlist supplied by the operator;
3. a TLS certificate and private-key file;
4. no wildcard Host entry.

Browser-reachable mode additionally requires an explicit Origin allowlist. The server retains
Host/Origin validation and constant-time Bearer comparison at the request boundary.

The HTTP application exposes:

- `/livez` for process liveness only;
- `/readyz` for dependency readiness;
- `/healthz` as the existing compatibility endpoint.

Readiness failure returns HTTP 503 and does not turn liveness into a dependency check. The runtime
readiness probe uses a non-mutating execution point lookup rather than materializing the full
execution table.

## Correctness invariants

1. At most one unexpired lease exists per execution.
2. Every takeover receives a newer fencing token.
3. A stale fencing token can never write an authoritative execution resolution.
4. A fenced-state resolution cannot bypass lease ownership.
5. Equivalent aware timestamps with different UTC offsets have identical lease semantics.
6. Lease ownership does not convert UNKNOWN into retry-safe state.
7. No Phase 6E path adds blind retry of an ambiguous external effect.
8. Reconciliation remains bound to the exact durable provider endpoint/effect identity from Phase
   6D.
9. Credentials and provider payloads are not stored in lease metadata or operational diagnostics.

## Deployment boundary

The SQLite implementation is a **single-host, multi-process** coordination primitive. It assumes
all participating processes open the same local filesystem database with SQLite locking semantics.
It is not a cross-host consensus protocol and no correctness claim is made for network filesystems
whose locking or durability semantics differ from local SQLite.

Horizontal multi-host HA requires a new implementation of the existing ports backed by a shared
transactional system with equivalent lease/fencing guarantees. That future adapter must prove the
same invariants before it can replace the SQLite implementation.

## Rejected alternatives

### Redis lock without fencing

Rejected. Mutual exclusion alone does not prevent a paused or partitioned stale worker from
committing after lock expiry.

### In-memory process lock

Rejected. It does not coordinate independent processes and disappears on crash.

### Immediate Kubernetes/Redis/PostgreSQL dependency

Rejected for this phase. It would increase operational surface without being required to prove the
single-host multi-process contract. The ports remain replaceable when real multi-host deployment is
needed.

### Automatic retry after UNKNOWN

Rejected. Phase 6 contract semantics remain `RECONCILE_BEFORE_RETRY` unless provider-specific
idempotency evidence proves a different policy.

## Consequences

DecisionLock can run a protected HTTP service and one or more reconciliation processes on one host
without duplicate authoritative resolution ownership. Crash recovery and takeover are explicit and
testable. The cost is a bounded lease delay after abrupt worker death and a deliberate limitation:
this phase does not claim distributed HA, distributed consensus, or cross-region failover.
