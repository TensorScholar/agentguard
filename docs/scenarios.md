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

**Run it.**

```bash
# An execution that ended UNKNOWN appears in durable state:
agentguard audit-verify --ledger .agentguard/demo/audit.sqlite

# Only a trusted provider-specific reconciler may resolve it.
agentguard reconcile-execution --execution-id <id> --evidence provider-evidence.json
```

`reconcile-execution` **deliberately rejects** file-supplied evidence claiming `PROVIDER_VERIFIED` or
`CONFIRMED_*` (`cli/app.py:615-623`), and `ProviderReconciliationEvidence` enforces the same rule at
the type level (`domain/provider_contracts.py:166-175`). Locally signed evidence can say an outcome is
*ambiguous*; it can never manufacture proof that a provider committed.

```json
{
  "status": "confirmed_succeeded",
  "source": "provider-status-tool",
  "evidence_digest": "sha256:<digest>",
  "observed_at": "2026-07-29T10:00:12Z",
  "trust_level": "provider_verified",
  "provider_operation_id": "ch_3Qd7Xk2eZvKYlo2C"
}
```

**Material:** [`examples/indirect-injection/`](../examples/indirect-injection) (how the injected
instruction gets there) and `examples/scoped-refund/` for the dispatch shape.
The `UNKNOWN` outcome arises naturally from a real timeout on a live upstream — there is no fixture
that fakes it, and inventing one would misrepresent the path. See
[Phase 2 debt](#phase-2-debt-from-this-scenario-work).

**Mechanisms exercised:** all four.

---

## What these scenarios do not show

- **No real provider integration.** The status-tool reconciliation contract is trusted configuration,
  not a claim about arbitrary MCP servers.
- **No production credential source.** Ceilings and late resolution are exercised against an
  environment-backed source. There is no audience proof and no native downscoping yet — see
  [Credential Contract](credential-contract.md#what-is-still-missing).
- **No bypass-route closure.** If the agent can reach the provider by another path, none of this
  applies. `mcp-posture` can detect bypasses in supplied configuration but cannot prove their absence.
- **Not the research result.** None of the above depends on the falsified differentiation thesis. See
  the [README Research Status](../README.md#research-status--read-this-before-evaluating-the-design).

---

## Phase 2 debt from this scenario work

| Item | Why |
|---|---|
| Irreversible-delete fixture (`examples/irreversible-delete/`) | Scenarios 1 and 3 currently share the refund fixture; a dedicated delete fixture would exercise the `deleted_files` / `records_modified` budget path end to end. |
| Reproducible `UNKNOWN` walkthrough | Scenario 3's ambiguous dispatch requires a live upstream. A committed fake-upstream recipe (server that accepts then drops the connection) would make the reconcile path demonstrable without a real provider. Deferred: it needs a new test-harness server, which is Phase 2 scope. |
| Per-scenario evidence bundles | Today all scenarios export from the shared demo bundle. Per-scenario bundles would make the audit story in each scenario directly verifiable. |
