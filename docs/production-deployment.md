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
- local SQLite ledger mode `0600`;
- exact one-use approvals;
- periodic signed checkpoint copied to a remote repository or object store.

### CI agent gateway

- immutable container image pinned by digest;
- read-only source mount where possible;
- ephemeral writable directory for ledger/evidence;
- no long-lived credentials in the agent environment;
- `mcp-posture` and changed-config gate run before agent tasks;
- signed evidence uploaded as a non-mutable build artifact.

### Enterprise service

RC2 is not a complete distributed service. Before horizontal scaling, implement the existing state
ports with a shared transactional store, central signer/HSM boundary, identity-backed approval
service, broker integration, telemetry export and policy distribution with rollback controls.

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
