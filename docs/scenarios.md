# High-Stakes Scenarios

Three concrete scenarios. Each one is a real thing an operator gets paged for, and each is wired to
runnable material in `examples/`. They exist to show *which* of the four wedge mechanisms matter in
which situation — not to imply breadth.

All three exercise the same spine: **credential ceiling + late resolution**, **mutation and replay
protection**, and **evidence export with offline verification**. Scenario 3 adds the ambiguous-effect
reconcile path.

---

## Scenario 1 — Bounded Refund (the canonical case)

**The failure.** A customer-support agent is approved to refund \$85. It holds a long-lived payments
token. A fetched support article contains injected text telling it to also export the address book, or
simply to "correct" the amount. Because the token is broad, one prompt injection reaches everything it
touches.

**What AgentGuard does.** The decision issues a ceiling scoped to *this* refund — audience, `refund:create`
scope, tenant `acme`, 60-second TTL. At dispatch the digest is recomputed from the live call, so the
\$850 variant fails with `execution.arguments_digest_mismatch`. An inflated credential fails with
`credential.scope_exceeds_decision`. Replaying the consumed receipt fails with
`decision_receipt.replayed`.

**Run it.**

```bash
agentguard demo --output .agentguard/demo --force
cat .agentguard/demo/results.json
```

```json
{
  "happy_path": "authorized",
  "argument_mutation": "execution.arguments_digest_mismatch",
  "excessive_scope": "credential.scope_exceeds_decision",
  "replay": "decision_receipt.replayed"
}
```

**Material:** [`examples/scoped-refund/`](../examples/scoped-refund) (runnable `request.json` +
`policy.yaml`), [`examples/argument-mutation/`](../examples/argument-mutation),
[`examples/excessive-scope/`](../examples/excessive-scope),
[`examples/replay/`](../examples/replay).
See [DEMO.md](DEMO.md).

**Mechanisms exercised:** 1 (ceiling + late resolution), 2 (digest + single-use), 4 (evidence).

---

## Scenario 2 — Irreversible Delete

**The failure.** An agent is approved to delete *one* expired record. A loop bug, a model retry, or an
intermediate result injected from tool output turns that into a bulk delete or a delete against the
wrong tenant. There is no undo.

**What AgentGuard does.** The same four mechanisms, with the blast-radius limits doing the work: the
decision's execution budget caps `deleted_files` and `records_modified`, and those caps are re-checked
against the live intent at execution time (`_check_budget`, `engine/execution.py:42-58`). Delete is a
high-impact action, so `production_mutation` in policy routes it to `REQUIRE_APPROVAL` rather than
auto-allow, and the approval receipt cannot exceed the decision's budget or outlive it.

**Run it.** Model the delete on the refund example — a `production_mutation` capability with
`deleted_files` and `records_modified` in `effects`, a `require_approval_capabilities` rule, and a
budget in the policy. The approval step is `agentguard approve`.

**Material:** [`examples/scoped-refund/policy.yaml`](../examples/scoped-refund/policy.yaml) shows the
approval-gated shape; no separate delete fixture ships yet — see [Phase 2 debt](#phase-2-debt-from-this-scenario-work).

**Mechanisms exercised:** 1 (ceiling), 2 (digest + single-use + budget re-check), 4 (evidence).

---

## Scenario 3 — External Effect That Goes UNKNOWN

**The failure.** A payment or bulk-export call is dispatched. The connection drops after the request
left but before the response arrived. **The client cannot tell whether it committed.** The agent
retries. It now may have moved money twice. This is the failure mode that plain idempotency keys and
plain audit logs do not solve, because nobody knows what to look up.

**What AgentGuard does.** The effect is bound *before* dispatch. A timeout yields `UNKNOWN`, never a
guess. `RECONCILE_BEFORE_RETRY` is the default `ReplayDisposition`, so a retry is only permitted once
stronger evidence exists. Reconciliation never auto-redispatches — it is operator- or
reconciler-driven.

**Run it.** This one is now fully reproducible:

```bash
pip install -e '.[http]'
python examples/harness/run_demo.py
```

The harness provider commits the refund, then **drops the connection**. The gateway times out and
records `UNKNOWN` with `retry_safe: false`; the provider's own ledger shows the refund **did**
happen. Then `agentguard-reconcile-worker --once` queries the provider's `refund.status` tool and
resolves the execution to `confirmed_succeeded` at `provider_verified` trust — **without
redispatching**. The provider ledger still holds exactly two refunds.

```
== E. Ambiguous effect stays UNKNOWN and is not retried
   PASS gateway refuses to guess (code -32004, retry_safe false)
   PASS provider actually committed despite the dropped connection -- 1 -> 2
   PASS AgentGuard recorded the execution as unknown -- exec_... -> unknown
== F. Reconcile-before-retry via the provider status tool
   PASS resolution is confirmed_succeeded at PROVIDER_VERIFIED trust
   PASS reconciliation did not redispatch -- still exactly 2 refunds
```

**Material:** [`examples/harness/`](../examples/harness) (provider, strict policy, driver),
[`examples/indirect-injection/`](../examples/indirect-injection) (how the injected instruction gets
there). **Read the harness README first** — the fake provider confirms from its own ledger, which
is not an external attestation.

**Mechanisms exercised:** all four.

---

## What these scenarios do not show

- **No real provider integration.** The status-tool reconciliation contract is trusted configuration,
  not a claim about arbitrary MCP servers. The harness provider confirms from its own ledger.
- **No production credential source beyond env-backed late resolution.** There is no audience proof
  and no native downscoping yet — see
  [Credential Contract](credential-contract.md#what-is-still-missing).
- **No bypass-route closure.** If the agent can reach the provider by another path, none of this
  applies. `mcp-posture` can detect bypasses in supplied configuration but cannot prove their absence.
- **A reconciliation resolution records no provider operation id.** The reconciler observes the
  provider's operation id and folds it into the evidence digest, but the frozen provider contract
  carries only a digest, so `execution_resolutions.provider_operation_id_digest` stays empty. Tracked
  as `AG-EVID-001`.
- **Not the research result.** None of the above depends on the falsified differentiation thesis. See
  the [README Research Status](../README.md#research-status--read-this-before-evaluating-the-design).

---

## Phase 2 debt from this scenario work

| Item | Why |
|---|---|
| `AG-EVID-001` — propagate the provider operation id into the resolution record | `ProviderReconciliationEvidence` observes `provider_operation_id` and digests it into `evidence_digest`, but `ReconciliationEvidence` only carries the digest, so the resolution's `provider_operation_id_digest` column is always empty. Closing it means an additive change to the frozen provider contract (ADR 0004), so it is deferred rather than slipped in. |
| Irreversible-delete fixture (`examples/irreversible-delete/`) | Scenarios 1 and 3 share the refund fixture; a dedicated delete fixture would exercise the `deleted_files` / `records_modified` budget path end to end. |
