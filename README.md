# AgentGuard

**Provider-neutral action authorization and execution integrity for AI agents.**

> Authorize the action. Bind the credential. Verify the execution. Prove the enforcement path.

AgentGuard converts a proposed agent action into a short-lived signed decision receipt, constrains
credentials to least privilege, rejects execution-time mutation and replay, and emits correlated,
tamper-evident evidence. It also scans MCP configurations for direct routes that bypass the proxy.

## Why this exists

Agent identity, tool policy, credential issuance, runtime execution and audit are usually separate
controls. The dangerous gaps are between them:

- an approved action can be executed with different arguments;
- a credential can exceed the approved audience, scope, tenant or lifetime;
- a permit can be replayed;
- an MCP client can retain a second direct route around the security gateway;
- a locally hash-chained ledger can be truncated or replaced without an external anchor;
- a self-consistent evidence bundle can be modified unless its manifest is authenticated.

AgentGuard targets these integrity gaps with deterministic controls rather than model judgment.

## Core invariants

```text
Authorized action == Credentialed action == Executed action
Every protected MCP route passes through AgentGuard
Retained evidence is redacted, integrity-checked and optionally signed
```

## Implemented in v0.2.0rc2

- Strict, versioned intent, policy, receipt, credential, execution, audit and evidence schemas.
- Policy v2 with default deny, deterministic deny precedence, tenant binding, provenance conditions
  and blast-radius budgets.
- Ed25519-signed, short-lived, request-bound decision and approval receipts.
- Full-intent canonical digest plus diagnostic field digests for every security-relevant input.
- Approval budgets that cannot expand the original decision.
- Credential grants bounded by audience, scope, tenant, TTL and decision validity window.
- Atomic issuance, approval-use and execution-nonce consumption in SQLite.
- MCP stdio enforcement with bounded messages, concurrent relay, fresh schema binding and
  fail-closed inventory behavior.
- Stable per-server MCP identity to prevent cross-server inventory and approval collisions.
- `mcp-posture` coverage scanning for direct, ambiguous and parallel bypass routes.
- Sensitive path, encoded path, raw host, decimal IPv4 and cloud-metadata protections.
- Defense-in-depth secret redaction at the audit persistence boundary.
- Owner-only permissions for ledgers, private keys and generated evidence.
- Explicit legacy-ledger sanitization and re-chaining migration.
- Hash-chained audit events plus signed external audit checkpoints.
- Closed-world evidence bundles with optional signed manifest attestations.
- HTTP transport validation primitives for Origin, Host and mirrored header/body values.
- Preserved v0.1 scanner, gate, doctor, reporting, approval and MCP compatibility workflows.

## Quick start

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e .

agentguard init
agentguard demo --output .agentguard/demo
agentguard evidence-verify .agentguard/demo/evidence \
  --public-key .agentguard/demo/public.pem --require-signature
```

## Authorize, broker and verify

```bash
agentguard authorize \
  examples/scoped-refund/request.json \
  examples/scoped-refund/policy.yaml \
  --output decision.json

agentguard broker-demo \
  examples/scoped-refund/request.json decision.json \
  --output grant.json

agentguard verify-execution \
  examples/scoped-refund/request.json decision.json \
  examples/scoped-refund/policy.yaml \
  --grant grant.json
```

## Prove MCP enforcement coverage

```bash
agentguard mcp-posture \
  --config examples/mcp_posture_protected.json \
  --fail-on-bypass
```

A direct route, invalid route, unverifiable proxy target or guarded-plus-direct duplicate causes the
command to fail when `--fail-on-bypass` is enabled.

## Anchor audit state outside the ledger

```bash
agentguard audit-checkpoint-create \
  --ledger .agentguard/audit.sqlite \
  --key .agentguard/decision-private.pem \
  --ledger-id workstation-17 \
  --output checkpoint.json

agentguard audit-checkpoint-verify checkpoint.json \
  --ledger .agentguard/audit.sqlite \
  --public-key .agentguard/decision-public.pem
```

Store `checkpoint.json` in an independent, append-only or remotely controlled location. A checkpoint
stored beside the ledger does not protect against complete host compromise.

## Legacy MCP compatibility

The CLI still exposes `doctor`, `scan`, `gate`, `check-call`, `proxy`, `approve-call`, `approvals`,
`mcp-proxy`, `report`, `verify-audit` and `sanitize-audit`.

Each `mcp-proxy` instance receives a stable source identity derived from the downstream command or
from `--server-id`. Bind exact approval grants to the same identity:

```bash
agentguard approve-call \
  --server-id filesystem-prod \
  --tool write_file \
  --arg path=README.md \
  --approved-by security \
  --reason "approved documentation update"

agentguard mcp-proxy \
  --server-id filesystem-prod \
  --policy .agentguard/policy.yaml \
  -- npx @modelcontextprotocol/server-filesystem .
```

## Product boundary

AgentGuard owns action normalization, deterministic authorization, receipt integrity, credential
ceilings, execution-time binding, local approval artifacts, MCP enforcement posture and evidence
correlation.

It does **not** own model evaluation, identity proofing, secret vaulting, agent orchestration, SIEM
storage, a hosted approval UI, distributed consensus or operating-system sandboxing. A protocol
adapter can only enforce traffic routed through it; `mcp-posture` reduces configuration blind spots
but cannot prove the absence of hidden network paths.

## Release status

**Hardened release candidate; not production-certified.** The repository includes a complete local
implementation, tests, CI definitions, packaging, Docker deployment guidance, threat model and two
review reports. A stable production release still requires public CI execution on the final commit,
real-client interoperability tests, an external penetration test, a broker integration or explicit
no-broker deployment profile, and a production pilot.

See:

- `docs/security-review-rc2.md`
- `docs/market-gap-analysis.md`
- `docs/production-deployment.md`
- `docs/limitations.md`
