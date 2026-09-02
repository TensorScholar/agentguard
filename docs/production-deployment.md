# Production deployment guide

## Promotion gate

Do not label a build production-ready until all of the following are true for the exact commit and
artifacts being deployed:

1. Linux, macOS and Windows CI jobs pass on Python 3.11, 3.12 and 3.13 as configured.
2. Ruff format/check, strict mypy, pytest, branch coverage, schema drift, architecture, secret scan,
   static security scan, package build, metadata check and wheel smoke all pass.
3. The wheel and source distribution checksums match the release manifest.
4. Real MCP clients and every supported downstream server pass interoperability and failure tests.
5. The deployment's MCP configurations pass `mcp-posture --fail-on-bypass`.
6. Signing keys are stored outside the model process and rotated through an approved procedure.
7. Audit checkpoints are exported to independent append-only storage.
8. Network egress, filesystem access and process permissions are restricted outside AgentGuard.
9. Backup, restore, corrupted-ledger and key-loss exercises are completed.
10. An independent security review and a production pilot have no unresolved critical findings.

## Deployment profiles

### Local developer gateway

- one AgentGuard process per downstream MCP server;
- explicit `--server-id` per server/environment;
- loopback HTTP binding by default;
- local SQLite ledger mode `0600`;
- exact one-use approvals;
- periodic signed checkpoint copied to a remote repository or object store.

### Single-host service gateway

Phase 6E supports a bounded single-host, multi-process topology:

- one or more protected HTTP gateway processes may share the durable core state;
- one or more reconciliation worker processes may contend for UNKNOWN executions through SQLite
  leases and monotonic fencing tokens;
- an expired worker lease may be taken over, but a stale token cannot commit an authoritative
  execution resolution;
- provider reconciliation remains evidence-bound and does not make UNKNOWN blindly retryable;
- startup recovery promotes stranded DISPATCHING work according to the existing execution contract;
- worker diagnostics are structured JSON and do not include credential material or raw provider
  response bodies.

For reconciliation workers, use the same local core-state database and provider-reconciliation
sidecar as the protected gateway. Keep the lease duration comfortably above the provider timeout;
the CLI enforces a minimum margin of more than five seconds.

### Remote HTTP listener

Loopback is the default. A non-loopback `agentguard-mcp-http` listener is rejected unless all of the
following are present:

- a non-empty access token from `--access-token-env`;
- at least one explicit `--allowed-host` value;
- both `--tls-certfile` and `--tls-keyfile` pointing to existing files;
- no wildcard Host entry.

If `--require-origin` is enabled, at least one `--allowed-origin` is also required. TLS termination
outside the AgentGuard process is not treated as equivalent by this CLI gate; a future deployment
adapter may define a separately reviewed trusted-proxy boundary.

Service probes:

- `/livez` indicates that the HTTP process is alive;
- `/readyz` checks durable-state readiness and returns 503 when the dependency probe fails;
- `/healthz` remains for compatibility with earlier Phase 6A/6B deployments.

### CI agent gateway

- immutable container image pinned by digest;
- read-only source mount where possible;
- ephemeral writable directory for ledger/evidence;
- no long-lived credentials in the agent environment;
- `mcp-posture` and changed-config gate run before agent tasks;
- signed evidence uploaded as a non-mutable build artifact.

### Multi-host enterprise service

The Phase 6E SQLite coordination contract is **not** distributed HA. Do not place the SQLite state
on a network filesystem and infer cross-host correctness from local tests. Horizontal multi-host
scaling requires a shared transactional adapter that proves equivalent lease/fencing guarantees,
plus the central signer/HSM, identity-backed approval, broker, telemetry and policy-distribution
controls appropriate to that deployment.

## Reconciliation worker

The installed `agentguard-reconcile-worker` entrypoint provides background provider reconciliation.
Operationally important controls include:

- `--owner-id` for a stable operator-chosen process identity when desired;
- `--lease-seconds` for ownership expiry;
- `--poll-seconds` for bounded polling;
- `--max-items-per-tick` for work bounding;
- `--once` for one bounded pass;
- `--health-check` for an executable readiness probe.

The one-shot `agentguard-reconcile` command participates in the same lease protocol so manual
operator reconciliation cannot silently race an active worker.

## Container

```bash
docker build -t agentguard:0.2.0rc2 .
docker run --rm agentguard:0.2.0rc2 --version
```

The image runs as a non-root user. Mount only the policy, public keys and required state directories.
Do not mount a host Docker socket or broad home directory into the container.

## Key handling

- Generate signing keys in a controlled process, not in model context.
- Restrict private keys to owner read/write and use a dedicated runtime account.
- Prefer an HSM/KMS-backed `Signer` implementation for a multi-user deployment.
- Distribute public keys independently from evidence and checkpoint artifacts.
- Include key identifiers and rotation dates in operational inventory.

## Audit operations

- Verify the chain before creating a checkpoint.
- Export checkpoints on a fixed cadence and after security-significant batches.
- Alert when a checkpoint prefix no longer exists or its hash differs.
- Run `sanitize-audit` only for legacy data migration and acknowledge that prior anchors become
  invalid; archive the original database under controlled evidence-retention procedures.
