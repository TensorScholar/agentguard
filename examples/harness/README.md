# Demo harness

A local fake MCP provider, a strict demo policy, and a one-command demo driver.

**None of this is part of the DecisionLock package.** It lives in `examples/`, is not
installed by `pip`, and has no third-party dependencies (standard library only). It exists
because the documented happy path needs *a real MCP upstream to protect*, and shipping one is
the only way to show the wedge working without asking you to already have an MCP server.

```bash
pip install -e '.[http]'
python examples/harness/run_demo.py            # full run, ~5 seconds
python examples/harness/run_demo.py --list     # list scenarios
python examples/harness/run_demo.py --keep     # keep .decisionlock-demo/ for inspection
```

Exit code 0 means every scenario passed.

## Files

| File | Purpose |
|---|---|
| `provider.py` | Fake MCP provider over Streamable HTTP. Keeps its own durable ledger. Commits, then drops the connection, on request (`--ambiguous`). |
| `policy.yaml` | Strict default-deny policy for `refund.create`. Denies unknown provenance, unknown capability, and unmatched tools. Nothing is relaxed to make the demo pass. |
| `run_demo.py` | Drives the real product CLIs as subprocesses and asserts the outcome. |

## What the demo proves

- A **side-effecting** `refund.create` is admitted under a decision-scoped credential ceiling,
  dispatched, and executed at the provider.
- The credential is **resolved late** and **never written** to any durable SQLite state, the
  provider ledger, or the evidence bundle.
- **Argument mutation** is refused with `execution.arguments_digest_mismatch`.
- **Receipt replay** is refused with `decision_receipt.replayed`, and scope inflation with
  `credential.scope_exceeds_decision`.
- An **evidence bundle** verifies offline with only the public key, and **tampering with the
  credential ceiling inside the bundle is detected**.
- When the provider commits and then **drops the connection**, DecisionLock records the execution
  `UNKNOWN` with `retry_safe: false` rather than guessing — while the provider's own ledger shows
  the refund **did** happen.
- Reconciliation resolves that `UNKNOWN` to `confirmed_succeeded` at `provider_verified` trust
  **without redispatching**: the provider ledger still holds exactly two refunds.
- The operator path **refuses** file-supplied evidence claiming `provider_verified`.

## What the demo does NOT prove

Read this before drawing conclusions.

- **Nothing about a real payment provider.** The fake provider confirms outcomes from *its own
  ledger*. That is not an attestation by Stripe or anyone else. The reconciler is only as
  trustworthy as the status tool you configure — DecisionLock cannot verify a provider's honesty.
- **Not a certification, benchmark, or penetration test.** No independent security review, soak
  test, or production pilot has been done for `0.2.0rc4`.
- **Not the research result.** Nothing here depends on the Freeze v2 outcome. See the
  [README Research Status](../../README.md#research-status--read-this-before-evaluating-the-design).
- **Single host only.** SQLite, one gateway process, one reconciler tick.
- **The capability classifier is keyword-based and advisory.** `refund.create` classifies as a
  write because its description says "writes" and "applies". A real provider whose description
  omits such words classifies as `unknown` and is denied under this policy — that is
  `policy.unknown_capability`, and it is the policy's job to decide whether to allow it.

## Why the provider keys on the JSON-RPC id

DecisionLock sets the downstream JSON-RPC `id` to its execution id
(`adapters/protocols/mcp/http_executor.py:73`), so the provider sees
`exec_...` as the request id. It records the refund under that key, and `refund.status` looks it
up by the same value. That is what lets the reconciler — which queries by
`binding.attempt.execution_id` — find the effect without DecisionLock and the provider sharing any
out-of-band state.

`refund.status` returns `structuredContent`, not just text, because the reconciler reads the MCP
structured-output channel (`adapters/reconciliation/mcp_http.py:187`).