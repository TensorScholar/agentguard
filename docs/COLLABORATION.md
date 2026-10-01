# Collaboration brief

For a first conversation. Written to be read in five minutes and to be honest enough that you can
decide whether a second one is worth your time.

## The problem, in seven lines

An agent that can call a tool can move money, delete data, and send mail. Most of what goes wrong is
not bad reasoning — it is that **the thing that was authorized and the thing that were executed were
allowed to drift apart**, with nothing afterwards able to prove it. Concretely: the agent holds a
long-lived broad-scope secret instead of a narrow one; an approved \$85 refund is dispatched as \$850;
a call times out after the provider committed, the client cannot tell, and it retries. Separately,
the audit log is a different artifact from the decision, so "was this authorized?" gets answered by
assertion. Existing controls answer adjacent questions: allowlists answer *which tools exist*,
OAuth answers *may this runtime call this server*, sandboxes answer *how bad is the blast radius*.
None of them bind *this approved call* to *this credential* to *this dispatched effect*.

## What this project is

A single-host Python library and CLI that binds a short-lived, decision-scoped **credential ceiling**
to a signed authorization, resolves the actual secret only at the last moment, revalidates the
canonical digest against the live call, claims the decision nonce atomically, binds the external
effect *before* it happens, and emits a hash-chained ledger plus signed evidence bundles a third
party can verify offline.

Four mechanisms, in order of what they stop:

1. **Decision-bound credential ceilings + late secret resolution** — a broad long-lived secret the
   agent cannot widen; scope/audience/tenant/TTL inflated beyond the decision.
2. **Execution-time digest revalidation + single-use claim** — argument mutation between authorizing
   and dispatching; receipt replay.
3. **Durable external-effect binding + reconcile-before-retry** — a duplicate irreversible side effect
   after a timeout.
4. **Hash-chained ledger + signed evidence bundles + offline verification** — audit logs that cannot
   be tied to the decision that produced them.

## What is demonstrably working today

`pip install -e '.[http]' && python examples/harness/run_demo.py` — about five seconds, 28 checks,
exit 0. It drives the real CLIs, not mocks, against a local fake MCP provider.

- A side-effecting `refund.create` is admitted under a ceiling scoped to that action, dispatched, and
  committed at the provider for exactly the authorized amount.
- The credential is resolved at dispatch and **never appears** in any durable SQLite state, the
  provider ledger, or the evidence bundle.
- Tampered arguments are refused with `execution.arguments_digest_mismatch`; a replayed receipt with
  `decision_receipt.replayed`; scope inflation with `credential.scope_exceeds_decision`.
- An evidence bundle verifies offline with only the public key, and an escalated credential ceiling
  edited into the signed bundle is detected.
- The central case: the provider **commits a refund and then drops the connection**. AgentGuard records
  `UNKNOWN` with `retry_safe: false` instead of guessing — while the provider's own ledger shows the
  refund happened. The reconciler then resolves it to `confirmed_succeeded` at `provider_verified`
  trust via the provider's status tool, **without resending the refund**. The provider ledger still
  holds exactly two refunds.
- The operator path refuses file-supplied evidence claiming `provider_verified`.

## Research honesty — read this part

We ran a pre-registered experiment (`AG-LINEAGE-PREREG-v1.0`, "Freeze v2", 10,800 trials) to test
whether this design differentiates from a competently implemented baseline. **It did not.**

```
RESEARCH_CLAIM                            = NOT_VALIDATED
AGENTGUARD_SPECIFIC_DIFFERENTIATION_THESIS = FALSIFIED_WITHIN_PROTOCOL
```

Both arms recorded **0 primary violations** (3,600 retained trials each); the completion difference was
`0.0` (exact McNemar `p = 1.0`). The measured cost was asymmetric: a **slot-hold ratio of 6.45
favoring the unguarded baseline**. The result is eligible for publication as a null-result note and
has not been published.

That explicitly does **not** mean the system is unsafe, and it does not prove it can never
differentiate. What it means is: **do not buy this expecting a demonstrated reduction in integrity
failures versus a good baseline. That claim is unsupported.**

What survives it: the mechanisms above are worth having or not on their own merits. In particular the
core admission-ticket pattern — a single-use signed ticket, digest-revalidated at dispatch — is **not
unique to this project** and is specified in external work (`draft-das-agentic-execution-finality-02`,
`draft-farley-acta-signed-receipts-03`). We found no prior art for the **credential ceiling derived
from the decision and resolved late**, which is the part we think is actually distinctive.

The commercial thesis is a hypothesis, not a finding. No claim of market demand, willingness to pay,
pilot success, or comparative superiority is established.

## Non-goals and limits

Not roadmap items — boundaries.

- **Multi-host, HA, or distributed consensus.** Single-host, multi-process, local SQLite.
- **Identity.** We bind identity a trusted integration supplies. We do not issue or verify workload
  identity. A `DecisionReceipt` is a **bearer ticket** inside its validity window; external work
  binds authority non-bearer, which is strictly stronger than what we ship.
- **A vault, IAM, or token minting.** One environment variable, read at dispatch, never persisted.
  No audience proof and no upstream revocation call. Because a static secret cannot be attenuated, we
  require the requested scope set to exactly equal the configured profile rather than claim least
  privilege we cannot enforce at the provider.
- **Sandboxing or egress control.** Deployment responsibility.
- **Production certification.** No independent penetration test, soak test, or production pilot. There
  is also **no green hosted CI run** — `make check` (lint, `mypy --strict`, coverage, schema drift,
  three security scans, release metadata) passes locally on the release commit, and hosted CI is
  blocked on runner capacity (`AG-CI-001`).
- **The capability classifier is keyword-based and advisory.** A provider whose description omits the
  words we look for classifies as unknown and is denied. That is a real ergonomic cost.

## What kind of collaboration we want

**A design partner on one high-stakes tool path.** Concretely: a team with a real MCP tool where a
duplicate or over-scoped side effect would actually cost something — payments, data deletion, bulk
export, permission changes. We would like to wire AgentGuard in front of exactly one tool, agree a
credential ceiling and a provider status tool, and find out what breaks.

What we would want to learn, and cannot learn alone:

1. **Is the credential ceiling the thing you actually want?** If you already solve this with a vault
   issuing short-lived scoped tokens, the ceiling is redundant and we should hear so.
2. **Does the `UNKNOWN` → reconcile path survive contact with a real provider?** We have only ever
   reconciled against our own fake ledger. A provider with no queryable status, or one whose status
   tool lies, is the obvious failure mode.
3. **Is the integration burden acceptable?** Our own experiment suggests enforcement costs latency.
   We would rather learn that cheaply from you than infer it.
4. **Is the evidence bundle something your auditors want?** Or is it a compliance-shaped artifact
   nobody asks for?

## What we are not asking for yet

- A production deployment commitment.
- A multi-host or HA requirement — we cannot meet it, and asking would waste your time.
- An SLA, support commitment, or response-time guarantee.
- Funding, or a purchase. This conversation is about whether the design is worth building on.
- Feedback on the MIT license or commercial terms.

## Practical

Python 3.11+. `pip install -e '.[http]'`. Single host, one process, local SQLite. No external services
required for the demo. MIT licensed.

If you want to try it before talking: the evaluation path in the [README](../README.md#evaluate-this-in-under-30-minutes)
runs in well under 30 minutes and needs no credentials.

If the honest answer is that your use case does not need this, that is a useful answer and we would
rather have it than a pilot we would both regret.