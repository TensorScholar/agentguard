# Production deployment guide

AgentGuard `0.2.0rc4` is a release candidate. This guide describes the validated deployment boundary; it does not certify a deployment as production-ready.

## Promotion gate

Do not label a build production-ready until all of the following are true for the **exact commit and artifacts** being deployed:

1. Linux quality jobs pass on Python 3.11, 3.12, and 3.13; Linux/macOS/Windows compatibility jobs pass on Python 3.13.
2. Ruff format/check, strict mypy, pytest, branch-traced coverage, schema drift, architecture, secret, static-security, release-metadata, Security, and CodeQL gates pass.
3. Repeated wheel builds are byte-identical and normalized source distributions compare identically under the release `SOURCE_DATE_EPOCH`.
4. Base-wheel and HTTP-extra clean installs pass, including installed HTTP/reconciliation entrypoints.
5. The deterministic SBOM, release manifest, and SHA-256 checksums are retained and match the released distributions.
6. The non-root container image builds and passes its package/HTTP-extra smoke checks.
7. Real MCP clients and every deployment-supported downstream profile pass interoperability and failure-path tests.
8. Deployment MCP configurations pass `mcp-posture --fail-on-bypass` and network/process controls prevent alternate routes.
9. Signing keys and provider credentials are stored outside model/tool control and rotated through an approved procedure.
10. Audit checkpoints are exported to independently controlled append-only or equivalent protected storage.
11. Backup, restore, corrupted-ledger, expired-lease/takeover, and key-loss exercises are completed.
12. An independent security review, long-duration soak test, and controlled production pilot complete without unresolved critical findings.

## Deployment profiles

### Local developer gateway

- one protected gateway per downstream profile as appropriate;
- explicit `--server-id` per server/environment;
- loopback HTTP binding by default;
- local SQLite state owned by the dedicated runtime account;
- exact bounded approval/authority semantics;
- periodic signed checkpoints copied to independently controlled storage when durability evidence matters.

### Single-host service gateway

The validated Phase 6E topology is bounded to one host:

- protected HTTP gateway processes may share the local durable core state;
- reconciliation workers contend for `UNKNOWN` executions through SQLite leases and monotonic fencing tokens;
- an expired worker lease may be taken over, but a stale token cannot commit authoritative resolution state;
- provider reconciliation remains evidence-bound and never makes `UNKNOWN` blindly retryable;
- explicit operator recovery allows classifying stranded DISPATCHING executions as UNKNOWN after external dispatcher quiescence is verified (automatic startup recovery is disabled);
- worker diagnostics are structured JSON and do not include raw credential material or provider response bodies.

All coordinating processes must use the same local filesystem database. Do **not** put the SQLite coordination database on a network filesystem and infer cross-host correctness from single-host tests.

### Remote HTTP listener

Install the HTTP extra and inspect the installed service command:

```bash
python -m pip install 'agentguard[http]==0.2.0rc4'
agentguard-mcp-http --help
```

Loopback is the default. A non-loopback listener is rejected unless all of these are configured:

- a non-empty access token sourced from `--access-token-env`;
- at least one explicit `--allowed-host` value;
- both `--tls-certfile` and `--tls-keyfile` referencing existing files;
- no wildcard Host entry.

If `--require-origin` is enabled, at least one `--allowed-origin` is also required. TLS termination outside the AgentGuard process is not treated as an equivalent trusted-proxy boundary by this CLI.

Service probes:

- `/livez` — process liveness only;
- `/readyz` — durable dependency readiness, returning HTTP 503 when the probe fails;
- `/healthz` — compatibility endpoint retained from the earlier HTTP profile.

### Credential authority

The included production-profile authority can resolve an explicitly configured environment-held provider secret late in the execution path. Configure `--credential-env`, the exact audience/scopes/provider identity, credential profile state, and broker signing key according to the deployment's secret-management policy.

Do not place provider secret values in policy, durable grants, reconciliation metadata, or operator diagnostics. The environment source is an integration boundary, not a replacement for a vault/KMS or provider-native token service.

### Reconciliation worker

`agentguard-reconcile-worker` provides background provider reconciliation. Important controls include:

- `--owner-id` for a stable operator-selected process identity when desired;
- `--lease-seconds` for ownership expiry;
- `--poll-seconds` for bounded polling;
- `--max-items-per-tick` for claimed-attempt bounding (busy leases do not consume attempt capacity);
- `--once` for one bounded pass;
- `--health-check` for executable durable-state readiness.

Keep lease duration comfortably above the configured provider timeout; the CLI enforces a safety margin. The one-shot `agentguard-reconcile` command participates in the same lease/fencing protocol and cannot silently race an active worker.

### CI agent gateway

- immutable container image pinned by digest;
- read-only source mount where possible;
- ephemeral writable directory for required state/evidence;
- no long-lived credentials exposed to the model process;
- bypass posture and changed-configuration gates before agent tasks;
- signed evidence/checkpoints exported as immutable build artifacts where required.

### Multi-host service

`0.2.0rc4` does **not** provide a distributed HA contract. Horizontal multi-host scaling requires a shared transactional state adapter that proves equivalent atomic reservation, lease, fencing, and durability semantics, plus the signer/HSM, identity-backed approval, telemetry, policy distribution, and rollback controls appropriate to that environment.

## Container

```bash
docker build -t agentguard:0.2.0rc4 .
docker run --rm agentguard:0.2.0rc4 --version
docker run --rm --entrypoint agentguard-mcp-http agentguard:0.2.0rc4 --help
```

The image runs as a non-root user and includes the HTTP extra. Mount only required policy/public-key/state paths. Never mount a host Docker socket or a broad home directory into the container.

## Key handling

- Generate signing keys in a controlled process, not model context.
- Restrict private keys to the dedicated runtime account.
- Prefer HSM/KMS-backed signer implementations for multi-user production deployments.
- Distribute public keys independently from evidence/checkpoint artifacts.
- Inventory key identifiers, custody, rotation, and revocation procedures.

## Audit operations

- Verify the retained chain before creating a checkpoint.
- Export checkpoints on a defined cadence and after security-significant batches.
- Alert when an independently retained checkpoint no longer matches the local retained prefix.
- Exercise restore, corruption detection, and key-loss behavior before promotion.
- Use legacy audit sanitization only as an explicit migration operation; it invalidates earlier anchors and requires controlled retention of the original evidence.
