# AgentGuard Progress Tracker

## Current Phase

**Q04 / P0 — Execution Admission Correctness**

Current engineering task: **Q04-01 — Atomic dispatch eligibility**.

Feature expansion remains frozen until the execution-admission correctness queue is closed or explicitly re-scoped.

## Repository Baseline

- Remote `main`: `c9d8f66d1b3669605f2b2d64ea9dc8b71f66b0a5` — merge of PR #14 preserving audited Q01/Q02 history.
- Preserved Q01 commit: `7effe3e203d2123f5e6d4733706f78613b1f7bb8`.
- Preserved Q02 commit / audited preflight head: `d8c4bccdbdf41cea349cf81acbba63e15611f1d7`.
- Q04-01 working branch: `hardening/q04-01-atomic-dispatch-admission`.
- Showcase baseline: `848db15534d311070dbbf1470b8ef3ad39f98709`.
- Declared release version: `0.2.0rc3`.
- Source divergence: reconciled. The two previously local-only Q01/Q02 commits are now preserved in GitHub history through PR #14.

## Completed

### Q01 — Evidence verification signature assurance

**Status: APPROVED within bounded scope.**

Supported behavior includes:
- unsigned evidence without a verification key may be integrity-checked without claiming signature verification;
- supplying a public key requires an attestation/signature to exist and verify;
- signed evidence with the correct trusted key reports successful signature verification;
- wrong-key, missing-signature-under-requirement, and tampered cases fail closed.

Boundary: cryptographic verification establishes authenticity relative to the trusted verification key; it does not establish provider business truth.

### Q02 — DecisionReceipt temporal hardening

**Status: PARTIAL, intentionally not closed.**

The protected execution path rechecks authorization expiry immediately before requesting the transition to `DISPATCHING`. This closes stale `RESERVED` dispatch in the no-contention case, but does not establish expiry correctness when SQLite write-lock acquisition blocks after the service sampled time.

### Q04-00 — Exact-source preflight

**Status: APPROVED for `d8c4bcc`.**

Validated in an isolated Python 3.12 environment with repository constraints:
- package version `0.2.0rc3`;
- `cryptography 50.0.1`;
- `pip check`: no broken requirements;
- targeted validation: exit code 0;
- full suite: exit code 0, 3 skipped.

This local preflight is acceptance evidence for the audited source head. It is not a substitute for GitHub-hosted CI.

## Current Work

### Q04-01 — Atomic dispatch eligibility

Target invariant:

> On the protected execution path, executor invocation requires a committed admission transition for the reserved authority. Receipt expiry and applicable field-integrity expiry are checked against fresh trusted time sampled inside the serialized transaction after acquiring the SQLite write lock.

Required proof sequence:
1. add a deterministic lock-contention regression that fails on the defective baseline for the intended reason;
2. acquire `BEGIN IMMEDIATE` before sampling admission time;
3. enforce receipt expiry and field-integrity expiry using that fresh in-transaction time;
4. commit `RESERVED -> DISPATCHING` before executor invocation;
5. prove zero executor calls when admission fails;
6. preserve normal execute, staged/commit, resumed reservation, replay/nonce, binding, and concurrent single-winner behavior.

## Next Milestones

1. Q04-01 atomic dispatch eligibility.
2. Q04-02 unsafe startup recovery containment.
3. Q04-03 exclude already-resolved reconciliation work.
4. Q04-04 reconciliation progress/fairness.
5. Q04-05 separate provider-response hashing from authorization canonicalization.
6. Q04-06 claims alignment.
7. Q04-07 integrated evaluation candidate.

These tasks must remain separate unless a correctness dependency proves otherwise.

## Security Guarantees Supported

Within the documented single-host/shared-local-SQLite mediation boundary, the implementation supports evidence for:
- strict structured action intent;
- deterministic default-deny policy evaluation;
- signed decision receipts and approvals;
- execution-time intent/policy binding checks;
- execution budgets and single-use authority consumption;
- delegated authority and capability leases;
- typed releases and causal ancestry;
- protected MCP boundaries;
- credential ceilings and late secret resolution;
- exact provider/endpoint binding;
- durable execution state and external-effect bindings;
- explicit ambiguous-outcome handling (`UNKNOWN`, `RECONCILE_BEFORE_RETRY`);
- reconciliation fencing and stale-worker rejection for authoritative resolution;
- hash-chained audit, signed checkpoints, evidence manifests, and execution attestations.

## Security Guarantees NOT Established

The project does **not** currently establish:
- unconditional equivalence between authorized action, credentialed request, and provider business effect;
- correctness of adapter-supplied business facts when trusted normalization is wrong;
- absence of hidden alternate execution routes around the mediation boundary;
- provider business truth solely from locally signed evidence;
- multi-host distributed coordination correctness;
- production certification, independent security review, or penetration-test assurance;
- Q04-01 lock-contention expiry correctness until the current task is completed and validated.

## Product Validation Status

Current product thesis remains a **HYPOTHESIS**:

> For a consequential agent workflow, AgentGuard preserves the binding between trusted business facts, authorization, credential-controlled submission and durable outcome evidence across pauses, crashes and caller retries, with materially less integration burden or fewer integrity failures than a competently implemented existing stack.

No claim of demonstrated market demand, willingness to pay, pilot success, or comparative production superiority is established yet.

## Release / Promotion Debt

Issue #12 remains open. Promotion debt includes:
- exact release-commit CI evidence;
- repository governance / branch protection where supported;
- signed commit/tag policy;
- artifact provenance / cryptographic attestation;
- backup/restore validation;
- corruption and key-loss drills;
- independent checkpoint retention;
- broader canonicalization assurance;
- independent security review / penetration testing;
- long soak / controlled pilot;
- operator ergonomics;
- provider-native IAM/downscoping where required.

## Latest Validation

- Q04-00 isolated exact-source preflight on `d8c4bcc`: targeted PASS, full suite PASS, 3 skipped.
- PR #14 GitHub Actions were runner-less infrastructure failures (`steps=[]`, `runner_id=0`) and therefore provide neither passing-CI evidence nor code-regression evidence.
- PR #14 merged as `c9d8f66d1b3669605f2b2d64ea9dc8b71f66b0a5` after bounded diff/self-review and exact-head local validation.

## Risks

- P0: receipt expiry can currently be evaluated using time sampled before SQLite write-lock acquisition, allowing admission after expiry under contention.
- Startup recovery can classify another process's live `DISPATCHING` execution as `UNKNOWN`.
- Reconciliation can repeatedly consume resolved work and starve later records.
- Provider-output hashing currently reuses stricter signing canonicalization and can mishandle finite float JSON outputs.
- Trusted normalization remains a fundamental TCB boundary.
- Stable logical business-operation identity can diverge from fresh AgentGuard authorization identity.
- Current repository CI capacity/governance debt limits hosted evidence quality.

## Decision Log

- Preserve Q01/Q02 exact commit identities; do not recreate or cherry-pick them. **Done via PR #14.**
- Do not treat runner-less GitHub Actions failures as code regressions or as passing validation.
- Do not loosen dependency constraints to accommodate environment drift.
- Keep SQLite and the modular-monolith architecture unless correctness evidence requires change.
- Keep Q04-01 bounded to dispatch admission; do not combine recovery, reconciliation, provider, crypto, dependency, CI, or showcase changes.
