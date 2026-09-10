# AgentGuard Progress Tracker

## Current Phase

**Q04 / P0 — Execution Admission Correctness**

Current engineering task: **Q04-06 — Claims alignment**.

Feature expansion remains frozen until the execution-admission correctness queue is closed or explicitly re-scoped.

## Repository Baseline

- Remote `main`: `f7338a9a0ef6e07b39f371cc4c17f93a72f4ec37`.
- Preserved Q01 commit: `7effe3e203d2123f5e6d4733706f78613b1f7bb8`.
- Preserved Q02 commit / audited preflight head: `d8c4bccdbdf41cea349cf81acbba63e15611f1d7`.
- Active working branch: `docs/q04-06-core-claims-alignment`.
- Reference repository: `TensorScholar/agentguard-reference`.
- Audited reference baseline: `029aa4b9eb8aee5d2be91d7f813369a248dd80b6`.
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

**Status: SUPERSEDED / CLOSED by Q04-01.**

The protected execution path rechecks authorization expiry immediately before requesting the transition to `DISPATCHING`. The remaining lock-contention race—where SQLite write-lock acquisition blocks after the service sampled time—was formally closed by Q04-01, which moved authoritative expiry checking inside SQLite `BEGIN IMMEDIATE` after serialized transition ownership.

### Q04-00 — Exact-source preflight

**Status: APPROVED for `d8c4bcc`.**

Validated in an isolated Python 3.12 environment with repository constraints:
- package version `0.2.0rc3`;
- `cryptography 50.0.1`;
- `pip check`: no broken requirements;
- targeted validation: exit code 0;
- full suite: exit code 0, 3 skipped.

This local preflight is acceptance evidence for the audited source head. It is not a substitute for GitHub-hosted CI.

### Q04-01 — Atomic dispatch eligibility

**Status: CLOSED / MERGED via PR #16 (`ceedcecef91ee475d7db6b7756e7020b8756b01b`).**

Executor invocation requires a committed admission transition where expiry is checked using trusted time after serialized transition ownership inside SQLite `BEGIN IMMEDIATE`.

### Q04-02 — Unsafe startup recovery containment

**Status: CLOSED / MERGED via PR #17 (`e21ace441535ca1e1bcd266b00aaf7befa800fdf`).**

Automatic startup recovery was removed because liveness of previous executors cannot be established from shared local state. Ambient startup invocations were removed from HTTP gateway startup, reconciliation worker startup, and protected MCP proxy startup. Explicit recovery (`recover_incomplete_executions()`) remains available for controlled operator invocation.

### Q04-03 — Exclude terminal reconciliation work

**Status: CLOSED / MERGED via PR #18 (`f0f4bc16bec2c08552b040b37b332e7bb32a500b`).**

Once an UNKNOWN execution has an authoritative terminal resolution (`CONFIRMED_SUCCEEDED`, `CONFIRMED_FAILED`, `CONFLICT`), it is excluded from automatic candidate selection by background reconciliation workers and rejected by default lease acquisition. This prevents terminal work from repeatedly consuming bounded worker capacity and starving pending executions.

Explicit operator-directed reconciliation retains the ability to re-check `CONFIRMED_SUCCEEDED` and `CONFIRMED_FAILED` resolutions via `claim_reconciliation_lease(..., allow_terminal_recheck=True)` (opted into by default in the one-shot operator CLI `agentguard-reconcile`). This preserves the core AgentGuard invariant that later contradictory `PROVIDER_VERIFIED` evidence can synthesize `CONFLICT` rather than relying on last-write-wins. Once an execution reaches `CONFLICT`, both background worker ticks and operator re-checks reject further lease acquisition. Non-terminal resolutions (`STILL_UNKNOWN`, `UNSUPPORTED`) remain eligible for future reconciliation. `executions.state` remains `UNKNOWN` permanently to preserve dispatch history.

Enforcement uses defense in depth:
- Authoritative atomic lease enforcement: `SQLiteFencedReconciliationState.claim_reconciliation_lease()` inspects the latest `execution_resolutions` within `BEGIN IMMEDIATE`. It unconditionally rejects `CONFLICT`, and rejects `CONFIRMED_SUCCEEDED` / `CONFIRMED_FAILED` unless `allow_terminal_recheck=True`.
- Worker prefilter optimization: `ReconciliationWorker.run_once()` checks `get_latest_execution_resolution()` and skips terminal records before bounded tick capacity is evaluated.

### Q04-04 — Reconciliation progress and fairness

**Status: CLOSED / MERGED via PR #20 (`f7338a9a0ef6e07b39f371cc4c17f93a72f4ec37`).**

A continuously running reconciliation worker uses process-local round-robin progression so a non-progressing early execution does not monopolize subsequent ticks. Busy leases do not consume reconciliation-attempt capacity.

Enforcement:
- Candidate rotation: At the start of `run_once()`, candidates snapshot is rotated so scanning begins immediately after the cursor execution from the previous tick. If the cursor is missing, it falls back to canonical storage order.
- Attempt capacity bounding: Bounded provider attempts are governed by successfully acquired leases (`claimed >= max_items_per_tick`), preventing busy leases from consuming quota and starving later actionable executions.
- Pre-reconciliation cursor advance: The cursor advances to the claimed execution ID immediately upon lease acquisition before provider reconciliation executes. A failing, `STILL_UNKNOWN`, or `UNSUPPORTED` candidate yields to subsequent executions on the next tick.

Explicit limitation: Fairness cursor state is process-local. Restarting the worker, or repeatedly invoking `--once` in separate processes, resets traversal to canonical storage order. No durable or cross-restart scheduler fairness is claimed or introduced.

### Q04-05 — Separate provider-response hashing

**Status: CLOSED / MERGED via PR #19 (`24e8d3eee606ac56fbaa6282a74a2d38fadd797b`).**

Provider-result hashing was separated from signed-authorization canonicalization. Authorization canonicalization continues to reject floating-point values to ensure cross-platform deterministic signing. Provider-result hashing normalizes finite JSON floating-point numbers without altering non-float types or signing canonicalization, allowing valid provider JSON payloads with finite floats to be reliably hashed and recorded without spurious conversion to `UNKNOWN`.

## Next Milestones

1. Q04-01 atomic dispatch eligibility (closed).
2. Q04-02 unsafe startup recovery containment (closed).
3. Q04-03 exclude already-resolved reconciliation work (closed).
4. Q04-04 reconciliation progress/fairness (closed).
5. Q04-05 separate provider-response hashing from authorization canonicalization (closed).
6. Q04-06 claims alignment (active).
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
- production certification, independent security review, or penetration-test assurance.

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

- Stale or orphaned `DISPATCHING` records require explicit reconciliation or controlled operator recovery; automatic startup recovery was removed.
- Background reconciliation worker fairness is process-local and resets to canonical storage order on worker restart or one-shot invocation; multi-host or durable fairness is not established.
- Trusted normalization remains a fundamental TCB boundary.
- Stable logical business-operation identity can diverge from fresh AgentGuard authorization identity.
- Current repository CI capacity/governance debt limits hosted evidence quality.

## Decision Log

- Preserve Q01/Q02 exact commit identities; do not recreate or cherry-pick them. **Done via PR #14.**
- Do not treat runner-less GitHub Actions failures as code regressions or as passing validation.
- Do not loosen dependency constraints to accommodate environment drift.
- Keep SQLite and the modular-monolith architecture unless correctness evidence requires change.
- Keep Q04-01 bounded to dispatch admission; do not combine recovery, reconciliation, provider, crypto, dependency, CI, or showcase changes. **Merged via PR #16.**
- Contain Q04-02 by removing ambient startup recovery without introducing distributed leases, new lifecycle states, or reconciliation redesign. **Merged via PR #17.**
- Exclude terminal reconciliation work (`CONFIRMED_SUCCEEDED`, `CONFIRMED_FAILED`, `CONFLICT`) via atomic storage enforcement in `claim_reconciliation_lease()` and worker optimization in `run_once()` while preserving `UNKNOWN` execution state. Keep Q04-04 progress/fairness separate. **Merged via PR #18.**
- Implement claimed-attempt quota bounding and process-local round-robin candidate rotation in `ReconciliationWorker.run_once()` so busy leases and non-progressing executions yield across ticks without introducing durable scheduler state. **Merged via PR #20.**
- Separate provider-result hashing (`canonical_json_bytes_for_provider_result`) from signed-security canonicalization (`canonical_json_bytes`), normalizing finite JSON floats while preserving strict float rejection for signed authorization objects. **Merged via PR #19.**
