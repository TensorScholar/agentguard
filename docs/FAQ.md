# FAQ and talking points

For a first call. Every answer here is also stated in the README or
[Limitations](limitations.md); this page is the short form, kept together because these are the
questions that actually come up.

## "Why not just use a policy gateway?"

You probably should, for most of what you need. That is not a criticism of gateways — a gateway is
the right tool for *which tools exist* and *what is allowed at all*, and it is what several vendors
already ship well.

The gap we are aiming at is narrower and different: the gateway answers a question **before** the
agent acts. We are asking what happens **between** a decision and the bytes that reach the provider,
where three specific things can go wrong:

1. The agent holds a secret broader than the action. A gateway can restrict *which tools* are
   reachable; it cannot stop the agent from using a long-lived token it already holds to call
   something else, directly, with `curl`.
2. The approved arguments are not the dispatched arguments. A gateway's allow/deny decision is made
   on the call as received; if authorization and dispatch are separated by anything — a retry, a
   wrapper, a queue, a different library — the decision can be applied to one representation and the
   effect produced from another.
3. A timeout after the provider committed. Neither a gateway nor an idempotency key can tell you
   whether this particular attempt committed. That needs the effect bound *before* dispatch and a
   reconciliation contract that forbids guessing.

If your risk is "the agent called a tool it should not have," use a gateway. If your risk is "the
approved action, the credential, and the external effect were the same thing," that is what this is.

## "Your own research says the thesis is falsified. Why should I look?"

You should read it before you look — it is the most useful thing here. We pre-registered an
experiment to test whether this design differentiates from a competently implemented baseline, and it
did not: **0 primary violations in both arms**, and a **6.45× slot-hold penalty for the guarded arm**.
So the claim "structured enforcement measurably reduces integrity failures" is unsupported and we do
not make it.

Two things follow. First, judge the mechanisms on their own merits — the credential ceiling, the
late resolution, the reconcile-before-retry contract, the evidence chain — none of which depend on
that result. Second, and more bluntly: we were measuring the wrong thing. The experiment found no
violations to prevent, which mostly tells you the harness scenarios do not generate adversarial
traffic. A null result that costs 6.45× latency is a reason to be skeptical of the *value
proposition*, not a reason to trust the enforcement.

## "What does the demo actually prove?"

It proves the plumbing works, end to end, with no mocks in the enforcement path:

- a side-effecting call is admitted under a decision-scoped ceiling and dispatched;
- the credential never reaches durable state, the provider ledger, or the evidence bundle;
- tampered arguments and replayed receipts are refused with stable reason codes;
- an ambiguous outcome is recorded `UNKNOWN` rather than guessed;
- reconciliation resolves it from provider evidence without resending;
- an evidence bundle verifies offline and detects tampering.

**It does not prove anything about a real provider.** The fake provider confirms outcomes from its own
ledger. That is not an attestation by Stripe or anyone else, and the reconciler is only as trustworthy
as the status tool you configure — AgentGuard cannot verify that a provider tells the truth. It is also
not a benchmark, a penetration test, a soak test, or a production pilot, and the capability classifier
it relies on is keyword-based and advisory.

## "Single-host only — is that intentional or just unfinished?"

It is a deliberate scope boundary, and it is the one we are most likely to regret.

Unfinished: the credential source is one environment variable, there is no audience proof and no
upstream revocation call, and we have not closed the provider-operation-id evidence gap.

Intentional: multi-host means distributed consensus over the nonce reservation, lease, and fencing
state. That is a large amount of very hard machinery, and we would rather ship one host that is
correct than five that are fast. It also means **we are not suitable if you need HA**, and we would
rather say so up front than take a pilot we cannot support.

## "Is this production-ready?"

No, and the repository is careful not to imply otherwise. It is `v0.2.0rc4`, an engineering-validated
release candidate. Missing: an independent security review, a long-duration soak test, and a
controlled production pilot.

CI evidence is **partial and we say which part**. Green self-hosted validation exists for this line —
`make check` at 839 passed, plus `pip_audit` and the MCP security gate. What is missing is green
*hosted* CI (it is `workflow_dispatch`-only since PR #30) and a cross-platform matrix (the evidence is
one combination: macOS / ARM64 / CPython 3.12.10). It is also not independent: the runner is our own
machine. `AG-CI-001` remains open for exactly those three reasons. See
[Project Status](project-status.md#ci-evidence-status).

## "Why MIT?"

Because the enforcement pattern is not the scarce part — it is specified in public IETF work, and we
would rather people implement it than pay for it. What we would want a commercial relationship to be
about is design partnership on the credential and evidence contracts, not licence fees. No commercial
model is defined yet.

## "A `DecisionReceipt` is a bearer ticket — isn't that a hole?"

It is a real limitation and it is weaker than the current external specification, which binds
authority non-bearer and sink-bound. Anyone who obtains a valid receipt inside its validity window can
spend it. We are not fixing it in this line; we are documenting it because it changes the threat model
you should evaluate against.

## "What would make you drop this?"

- Your credential needs are already met by scoped short-lived tokens from a vault. Then the ceiling is
  redundant.
- Your provider has no queryable status. Then reconcile-before-retry has nothing to reconcile against
  and the honest answer becomes "do not retry, page a human" — which is a worse product.
- Integrating it costs more integration effort than the risk it retires. Our own experiment makes this
  a live possibility.