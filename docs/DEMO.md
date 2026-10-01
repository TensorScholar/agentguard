# AgentGuard Demo: the Wedge Happy Path

The invariant this walkthrough demonstrates:

$$\text{authorized action} \;=\; \text{credentialed action} \;=\; \text{executed action}$$

The path below is the **whole supported happy path**: authorize → execute through the protected proxy
→ export evidence → verify offline, with an operator reconcile step for ambiguous effects. Everything
else in the CLI is listed in the README's
[Advanced Surface](../README.md#advanced-surface-not-part-of-the-wedge) and is not part of this
walkthrough.

Setup (once):

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e '.[http]'
```

---

## 0. One Command, Everything (~5 seconds)

```bash
pip install -e '.[http]'
python examples/harness/run_demo.py
```

This is the recommended starting point. It starts a local fake MCP provider, starts the protected
gateway with the **production** credential authority, and drives the real CLIs as subprocesses —
so what you see is what an operator gets, not a mock of the library.

```
== A. Argument mutation is blocked
   PASS tampered amount refused with execution.arguments_digest_mismatch
== C. Authorized side effect is dispatched
   PASS refund.create admitted and dispatched
   PASS provider committed the authorized amount -- amount_minor=8500
== Credential handling
   PASS secret never written to any durable sqlite state
== B. Receipt replay is blocked
   PASS second dispatch of a consumed receipt refused (decision_receipt.replayed)
== D. Evidence export, offline verify, tamper detection
   PASS offline verify: signature verified -- {"ok": true, "signature_verified": true}
   PASS escalated credential ceiling in the bundle is detected
== E. Ambiguous effect stays UNKNOWN and is not retried
   PASS gateway refuses to guess (code -32004, retry_safe false)
   PASS provider actually committed despite the dropped connection
== F. Reconcile-before-retry via the provider status tool
   PASS resolution is confirmed_succeeded at PROVIDER_VERIFIED trust
   PASS reconciliation did not redispatch -- still exactly 2 refunds
```

28 checks, exit code 0.

**Read [`examples/harness/README.md`](../examples/harness/README.md) before drawing conclusions.**
The fake provider confirms outcomes from its own ledger; that is not an external attestation, and
none of this is a certification, benchmark, or penetration test.

The sections below walk the same path by hand.

---

## 1. Fixtures and the attack suite

```bash
agentguard demo --output .agentguard/demo --force
```

This runs the bounded-refund scenario ([Scenario 1](scenarios.md#scenario-1--bounded-refund-the-canonical-case))
through the kernel: golden path, then argument mutation, then scope inflation, then receipt replay,
then evidence packaging.

```bash
cat .agentguard/demo/results.json
```

```json
{
  "happy_path": "authorized",
  "argument_mutation": "execution.arguments_digest_mismatch",
  "excessive_scope": "credential.scope_exceeds_decision",
  "replay": "decision_receipt.replayed",
  "audit": [true, 7, "226e2386…f38a", null]
}
```

Each attack was stopped by a stable reason code **before** protected dispatch. The reason codes are
the contract; the demo prints them.

---

## 2. Authorize

```bash
agentguard authorize \
  examples/scoped-refund/request.json \
  examples/scoped-refund/policy.yaml \
  --key .agentguard/demo/private.pem \
  --ledger .agentguard/demo/audit.sqlite \
  --output .agentguard/demo/manual-decision.json
```

Produces a signed `DecisionReceipt` carrying the canonical SHA-256 intent digest **and the
`credential_ceiling` for this specific refund** — audience, scopes, tenant, TTL. That ceiling, not the
caller's request, is what bounds the credential. See
[Credential Contract §1](credential-contract.md#1-the-decision-issues-a-ceiling).

## 3. Resolve the credential

**Production path** (late resolution, real secret) — the Streamable HTTP gateway:

```bash
export PAYMENTS_API_TOKEN='...'

agentguard-mcp-http \
  --policy examples/scoped-refund/policy.yaml \
  --key .agentguard/demo/private.pem \
  --server-id customer-operations \
  --upstream-url https://payments.internal/mcp \
  --credential-env PAYMENTS_API_TOKEN \
  --credential-audience payments \
  --credential-scope refund:create \
  --access-token-env AGENTGUARD_HTTP_ACCESS_TOKEN
```

**Contract-test path** (no secret source) — for demos and tests only:

```bash
agentguard broker-demo \
  examples/scoped-refund/request.json \
  .agentguard/demo/manual-decision.json \
  --output .agentguard/demo/manual-grant.json
```

> `broker-demo` uses the **mock broker**. It exercises grant signing and ceiling enforcement without a
> secret source and **must not be treated as a production credential provider**. The production
> credential authority is reachable only via `agentguard-mcp-http --credential-env`. Full contract:
> [credential-contract.md](credential-contract.md).

## 4. Preflight (does **not** execute)

```bash
agentguard verify-execution \
  examples/scoped-refund/request.json \
  .agentguard/demo/manual-decision.json \
  examples/scoped-refund/policy.yaml \
  --grant .agentguard/demo/manual-grant.json \
  --public-key .agentguard/demo/public.pem \
  --state .agentguard/demo/audit.sqlite
```

This re-derives the canonical digest, verifies the receipt signature, checks the grant does not exceed
the ceiling, and re-evaluates the current policy.

It then prints, by design:

```
Execution authority verified; nonce not consumed. Use protected execution to claim authority.
```

**The name is misleading and the message is the truth.** `verify-execution` is a *preflight*: it mutates
nothing and consumes no nonce, so it provides no replay protection. Use it to debug a decision. (It was
`authorize_execution` until Phase 0, which was a worse name — see
[ADR 0001](adr/0001-action-integrity-kernel.md).)

## 5. Execute through the protected proxy

This is the real execution sink, and the only step that claims single-use authority:

```bash
agentguard mcp-proxy-v2 \
  --policy examples/scoped-refund/policy.yaml \
  --server-id customer-operations \
  --key .agentguard/demo/private.pem \
  --state .agentguard/demo/action-integrity.sqlite \
  -- <your-mcp-server-command>
```

For every call the proxy, in one `BEGIN IMMEDIATE` transaction:

1. recomputes the canonical digest **from the live call** and compares it to the signed digest;
2. re-evaluates the current policy and requires the matched rules to be identical;
3. clamps the resolved credential to the receipt's ceiling;
4. claims the nonce, decrements any capability lease, consumes any typed release, and writes durable
   `RESERVED` state;
5. persists an `ExternalEffectBinding` **before** the side-effecting dispatch;
6. dispatches, and classifies the result as definite or `UNKNOWN`.

## 6. Export and verify evidence offline

```bash
agentguard evidence-build \
  examples/scoped-refund/request.json \
  .agentguard/demo/manual-decision.json \
  --grant .agentguard/demo/manual-grant.json \
  --key .agentguard/demo/private.pem \
  --output .agentguard/demo/evidence-bundle

agentguard evidence-verify .agentguard/demo/evidence-bundle \
  --public-key .agentguard/demo/public.pem \
  --require-signature
```

```json
{"ok": true, "checked_artifacts": 3, "signature_verified": true}
```

A third party holding only the bundle and the public key can confirm that the digests match, the
manifest was signed by the trusted decision key, and nothing was altered or detached. They do not need
access to AgentGuard, the ledger, or the provider.

To prove no secret leaked into the bundle:

```bash
grep -R "$PAYMENTS_API_TOKEN" .agentguard/demo/evidence-bundle \
  && echo "LEAK" || echo "no secret in bundle"
```

---

## 7. Reconcile an ambiguous effect (operator path)

If a dispatch times out, the execution is `UNKNOWN` and is **never auto-retried**. See
[Scenario 3](scenarios.md#scenario-3--external-effect-that-goes-unknown).

```bash
# Find it
agentguard audit-verify --ledger .agentguard/demo/audit.sqlite

# Only a trusted provider-specific reconciler may resolve it
agentguard reconcile-execution --execution-id <id> --evidence provider-evidence.json
```

`reconcile-execution` rejects file-supplied evidence claiming `PROVIDER_VERIFIED` or `CONFIRMED_*`.
Locally signed evidence can record that an outcome is *ambiguous*; it cannot manufacture proof that a
provider committed. Reconciliation never auto-redispatches.

A crashed executor leaves a `DISPATCHING` record that needs **explicit** operator recovery
(`recover_incomplete_executions()`); automatic startup recovery was removed because executor liveness
cannot be established from shared local state. See [Limitations](limitations.md).

---

## Bypass detection (optional)

`mcp-posture` audits supplied MCP client configuration for unmediated direct routes. It detects bypasses
in the configuration you give it; it cannot prove none exist.

```bash
agentguard mcp-posture --config examples/mcp_posture_protected.json --fail-on-bypass  # 0 bypasses
agentguard mcp-posture --config examples/mcp_posture_bypass.json    --fail-on-bypass  # exits non-zero
```

---

## Legacy fixtures

`agentguard demo` also exports v0.1 compatibility fixtures to `.agentguard/demo/v1-compat/`. The v0.1
commands (`scan`, `gate`, …) remain available and are documented in the README's
[Advanced Surface](../README.md#advanced-surface-not-part-of-the-wedge).
