# AgentGuard Progress Tracker

## Current Phase

Current product status is [Project Status](project-status.md). Freeze v2 governance is recorded in [Freeze v2 result adjudication](research/FREEZE_V2_RESULT_ADJUDICATION.md). Q04-06 is not the active engineering task. The Q01–Q05 entries below stay as historical records.

This tracker does not change the Freeze v2 research claim. Production certification is not claimed.

## Repository Baseline

- Remote `main`: `5275e94f28a7c4282908d2fc88f5a44f2c3a7583`.
- Declared release version: `0.2.0rc4`.
- Current status document: `docs/project-status.md`.
- Freeze v2 adjudication: `docs/research/FREEZE_V2_RESULT_ADJUDICATION.md`.
- Preserved Q01 commit: `7effe3e203d2123f5e6d4733706f78613b1f7bb8`.
- Preserved Q02 commit / audited preflight head: `d8c4bccdbdf41cea349cf81acbba63e15611f1d7`.
- Historical reference-repository Q04-06 pins, not the current reference release: baseline `30b018239d56d600015e6ca2d2baeb0dde193ce6`, head `8ed4632105c4067e7d0c68a0f3e469f4f5a5bca8`.
- Reference repository: `TensorScholar/agentguard-reference`, package `1.0.1` — historical record only. That repository has since been removed; the pins above are retained solely as history.
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
- package version `0.2.0rc4`;
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
6. Q04-06 claims alignment (historical; superseded by Freeze v2 adjudication).
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

The product thesis was narrowed in Phase 1. It remains a **HYPOTHESIS** — narrowing a thesis does not
validate it:

> **Product thesis.** AgentGuard protects high-stakes MCP tool calls by binding a short-lived,
> decision-scoped credential ceiling to a signed authorization, resolving the actual secret only at the
> last moment, preventing replay and argument mutation, and producing independently verifiable evidence
> of what was authorized versus what was observed — especially for actions that can leave ambiguous
> external effects.

The commercial hypothesis attached to it is unchanged and still unvalidated:

> An operator will adopt and pay for the credential-ceiling and evidence chain specifically, rather than
> for general runtime authorization, at an integration burden low enough to be worth it.

No claim of demonstrated market demand, willingness to pay, pilot success, or comparative production
superiority is established yet.

**What the narrowed thesis does and does not rest on.** It does not rest on the Freeze v2 result: the
ceiling, the late resolution, the reconcile-before-retry contract, and the evidence chain are mechanisms
whose value is independent of whether structured enforcement measurably reduces integrity failures
against a baseline. It does rest on credential-ceiling adoption being a real problem buyers recognise
and are willing to integrate — which is untested. The core admission-ticket pattern is prior art
(`draft-das-agentic-execution-finality-02`, `draft-farley-acta-signed-receipts-03`); the ceiling bound
to that decision is the part with no prior art found.

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

## Phase 0 — Stabilization and Honesty

Decisions recorded for the stabilization pass. Each is a correction to existing behavior or
documentation; none adds a product feature.

- Publish the research outcome in `README.md` rather than only in `docs/research/`. The repository
  now states `RESEARCH_CLAIM: NOT_VALIDATED`, `AGENTGUARD_SPECIFIC_DIFFERENTIATION_THESIS:
  FALSIFIED_WITHIN_PROTOCOL`, the 6.45 slot-hold ratio favoring the no-guard baseline, the §6 scope
  exclusions, and the unestablished product claims, above the fold.
- Close the v1 fail-open policy default. `load_policy` and the `Policy` dataclass now default
  `default_action` to `deny`. Shipped v1 example policies and policy packs carry explicit
  `allowed_tools` allowlists, which are checked first and deny every tool they do not name. Policy v2
  is unchanged. This is a **breaking change** for any policy relying on implicit allow-by-default.
- Rename `authorize_execution` to `preflight_execution` and keep the old name only as a deprecated
  wrapper that emits a `DeprecationWarning`. The function has been non-consuming since the Q02
  supersession; the old name implied single-use enforcement it never performed.
- Exclude `agentguard.research` from the wheel and sdist. The pre-registered experiment is retained
  in the repository as the research record but is not shipped as unreferenced product code. Coverage
  measurement is aligned to the distributed package, which restores a real margin above the 80%
  combined statement/branch floor.
- Make CodeQL able to fail a build: add `security-events: write`, remove `upload: never`, and keep
  the SARIF artifact upload as retained evidence.
- Reconcile `docs/project-status.md` with the runner-less CI record. "Cross-platform CI gates" is
  removed from the validated-capabilities list and an explicit CI evidence status section is added,
  because no green hosted run exists on this line. Added as promotion debt `AG-CI-001`.
- Re-enable Dependabot for pip and GitHub Actions; the pause dates from the RC2 demonstration and is
  lifted.
- Pin the build backend by hash (`requirements/build-hashed.txt`) and build with `--no-isolation` so
  the build does not depend on whatever the index serves. Full hash pinning of the platform-specific
  runtime closure is recorded as `AG-SUP-001` rather than guessed at.
- Record supersession rather than only forward decisions: ADR 0003 superseded by ADR 0005; ADR 0006
  §7 superseded by ADR 0007; ADR 0001 annotated with the Q02 → Q04-01 supersession and the preflight
  rename; ADR 0002 annotated with the v1 default-deny alignment.

## Phase 1 — Define the Wedge and Kill Complexity

Product-focus decisions. No feature was added, no module was deleted, and no behavior changed. The
change is to what the project leads with and what a reader is shown first.

The problem this phase addresses: the surface was broad enough that a reader could not tell what the
product *is*. Seven README sections, 34 CLI subcommands, and a 16-item "validated capabilities" list
implied a general agent control plane. That is not what this project is competitive at, and leading with
it invited comparison against gateway vendors on breadth — a comparison this project loses.

Decisions recorded:

- **Narrow the thesis to four mechanisms.** Decision-bound credential ceilings with late secret
  resolution; execution-time digest revalidation with single-use claim; durable `ExternalEffectBinding`
  with `RECONCILE_BEFORE_RETRY`; hash-chained ledger with signed evidence bundles and offline
  verification. Stated as a single paragraph in the README, `docs/product-boundary.md`, and the Product
  Validation Status above.
- **State non-goals first.** `docs/limitations.md` now opens with the six non-goals (multi-host/HA,
  identity, generic policy-gateway competition, vault/token minting, isolation/egress, production
  certification) so a non-fit disqualifies itself in one read.
- **Demote, do not delete.** Causal graphs, field provenance and typed releases, policy counterfactuals,
  delegated authority trees, approval receipts, checkpoint signing, attestations, the reconciliation
  worker, and the v0.1 compatibility CLI move to an explicit
  [Advanced Surface](../README.md#advanced-surface-not-part-of-the-wedge) table in the README with a
  statement that no product claim depends on them. `project-status.md` splits "validated engineering
  capabilities" into product wedge versus advanced surface. All code, tests, and support remain.
- **Collapse the happy path to four steps.** `authorize` → `mcp-proxy-v2` (or `agentguard-mcp-http`) →
  `evidence-build` → `evidence-verify`, with `reconcile-execution` as an operator-only branch. The
  advanced commands are removed from the quick-start flow in both the README and `docs/DEMO.md`.
- **Correct a documentation error found while doing this.** The README and DEMO both described
  `verify-execution` as executing and as recording the decision nonce. It is a *preflight*: it mutates
  nothing, consumes no nonce, and prints "Execution authority verified; nonce not consumed. Use
  protected execution to claim authority." Both documents now state this, and the happy path points at
  the protected proxy as the real execution sink. This was a live correctness defect in the docs, not
  a wording preference.
- **Document the credential contract precisely.** New `docs/credential-contract.md` writes out ceiling
  issuance, request validation, grant shape, late resolution, header-injection constraints, and a
  table of where the secret never goes. It records that a static secret cannot be attenuated, so exact
  scope equality is required rather than claiming unenforceable least privilege
  (`adapters/broker/production.py:250-252`); that there is no audience proof and no upstream revocation
  call; and that `broker-demo` uses the non-production mock broker while the production authority is
  reachable only via `agentguard-mcp-http --credential-env`.
- **Add three concrete scenarios.** New `docs/scenarios.md`: bounded refund, irreversible delete, and an
  external effect that goes `UNKNOWN`. Each states which mechanisms it exercises and links to the
  existing `examples/` material, including the honest admission that the `UNKNOWN` path has no fixture
  because faking it would misrepresent the mechanism.
- **Surface the 5-minute/30-minute evaluation path.** The README states explicitly who the product is
  for, how long it takes to grasp and evaluate it, and that the core admission-ticket pattern is prior
  art so a buyer is not sold something they can get from a spec.

New debt items introduced by this phase are listed in `docs/credential-contract.md` and
`docs/scenarios.md` under their respective Phase 2 tables.

## Phase 2 — Practical MVP of the Wedge

The goal was narrow: a platform or security engineer can protect one high-stakes MCP tool path, see
mutation and replay blocked, export and independently verify evidence, and understand the reconcile
path — in under 30 minutes, from the primary docs alone. No new product surface, no research, no
multi-host work.

The demo now runs in **~5 seconds**, 28 checks, exit 0.

### Gaps found by running the documented path, and fixed

Each of these made the documented happy path fail for a new user. All were found by executing it,
not by reading it.

1. **Tool description was discarded before capability classification.** `intent_from_tools_call`
   rebuilt a `{"name", "inputSchema"}` dict for `classify_tool_definition`, and both the HTTP and
   stdio schema caches dropped `description` when building the bound schema. A tool whose capability
   is only inferable from its description therefore classified as `unknown` — which a default-deny
   `unknown_capability` then rejected. The strict happy path was unusable against most real MCP
   servers. Fixed in `intent.py`, `http_gateway.py`, and `protected.py`. This also *strengthens*
   schema binding: provider-declared semantics now participate in the schema digest, so a provider
   cannot silently change a tool's meaning without detection.
2. **No MCP adapter ever supplied provenance.** All three protected adapters called
   `intent_from_tools_call` without `provenance`/`provenance_verified`, so every live MCP intent was
   `(unverified, False)` and any policy with `unknown_provenance != allow` refused every call.
   Added `--provenance` / `--provenance-verified` to `mcp-proxy-v2` and `agentguard-mcp-http`, defaulting
   to `unverified`. The parser lives in `cli/io.py` and rejects unknown labels and the contradictory
   `unverified` + trusted mix.
3. **`agentguard init` never created the key `agentguard-mcp-http` expects.** The gateway defaults
   `--credential-key` to `.agentguard/credential-broker-private.pem` with key id
   `credential-broker-ed25519`, but `init` only wrote `broker-private.pem` (`mock-broker-ed25519`).
   Following the documented setup made the production credential path fail immediately. `init` now
   writes both.
4. **Stable reason codes were rendered as Rich tracebacks.** `ExecutionGuardError`,
   `EvidenceVerificationError`, `ServiceDeploymentError` and friends carry the code operators and CI
   match on, but the code was buried in a traceback. The entrypoint now prints
   `<Type>: <reason_code>` on stderr and exits 2.
5. **The gateway swallowed the credential reason code.** It reported only
   `CredentialAuthorityError`, making eight distinct credential failures indistinguishable. It now
   includes `error.data.reason_code`, e.g. `credential.profile_scope_mismatch`. A missing
   `--credential-key` file is caught at startup with a message naming `agentguard init`.
6. **The documented execution sink needed an MCP server the reader did not have.** `-- <your-mcp-server-command>`
   made the primary path unrunnable without an existing server. Added `examples/harness/`: a
   stdlib-only fake provider with its own durable ledger, a strict default-deny demo policy, and a
   driver that exercises the real CLIs as subprocesses. Not installed by `pip`; lives in `examples/`.
7. **The provider must key effects on the AgentGuard execution id.** The reconciler queries by
   `binding.attempt.execution_id`, and AgentGuard sets the downstream JSON-RPC `id` to exactly that
   value. The harness provider records and looks up on that id, so reconciliation needs no
   out-of-band shared state. Its `refund.status` returns `structuredContent`, which is the channel
   the reconciler reads.

### What was deliberately not done

- **No propagation of the provider operation id into resolutions.** The reconciler observes it and
  folds it into `evidence_digest`, but `ReconciliationEvidence` carries only a digest, so
  `provider_operation_id_digest` stays empty. Fixing it is an additive change to the contract frozen
  by ADR 0004 and is recorded as `AG-EVID-001` rather than slipped in.
- **No new credential provider.** The env-backed source is the documented happy path. No Vault, no
  IAM, no minting. The brief made a thin adapter optional and it would not have improved the demo,
  since the demo needs exactly one env-backed source to be honest about.
- **No fuzzing campaign, no CI changes, no changes to the research claim.** The research result stands
  exactly as adjudicated.
- **No new CLI commands.** Two flags were added to existing entrypoints; everything else reuses
  commands that already existed.

## Phase 3 — Packaging and Positioning

Goal: make the project evaluable by an external engineer and collaboration-ready, without adding
product surface. No new mechanisms, no CLI expansion, no behavior change except where a packaging or
documentation bug forced a fix.

Decisions recorded:

- **Cut `0.2.0rc4`.** Phases 0–2 were verified but sat under an "Unreleased" heading above the
  shipped `0.2.0rc3`, so an installed artifact contained all the Phase 0–2 code while advertising a
  version number that previously meant a different tree. Two people pinning `0.2.0rc3` could have
  received different code, which contradicts `release-process.md`'s own rule that releases are
  evidence-bound to an exact commit. `0.2.0rc4` is the release candidate that contains Phases 0–2, and
  the two versions are not interchangeable. Version metadata, CITATION, and the changelog heading are
  updated together; `check_release_metadata.py` enforces the match.
- **Fixed a packaging defect found by inspecting the artifact.** `MANIFEST.in` included `examples/`
  by `*.md *.json *.jsonl *.yaml` but not `*.py`, so an sdist consumer received the harness README
  telling them to run `run_demo.py` without receiving `run_demo.py`. Added `*.py`. Verified: the
  sdist now carries all four harness files, the wheel still carries none of them, and
  `src/agentguard/research` remains excluded from both.
- **Rebuilt and verified rather than assumed.** Wheel byte-identical across two `--no-isolation`
  builds; normalized sdist byte-identical; `twine check` PASSED on both; a clean install from the
  sdist reports `0.2.0rc4`, cannot import `agentguard.research`, and exposes `--provenance`.
- **Added a cold-start evaluation path** to the README as the first section an outsider meets: install,
  run the demo, verify evidence and detect tampering, then read the credential contract and
  limitations. Fixed two defects in my own instructions while writing it: the evidence commands wrote
  to `/tmp`, which AgentGuard correctly refuses on macOS because `/tmp` is a symlink, and the failure
  cascaded confusingly. Both steps were then executed verbatim from a clean virtualenv.
- **Added `docs/COLLABORATION.md`** — problem, four mechanisms, what is demonstrably working, the
  falsified-thesis result and what survives it, non-goals, the collaboration we want, and what we are
  not asking for. Modest and specific; no hype.
- **Added `docs/FAQ.md`** — the four questions that decide whether there is a second conversation.
- **Restructured `docs/project-status.md` for external eyes**: a delivery-history table for Phases 0–3,
  promotion debt grouped into what blocks a pilot, what blocks a credential-path production claim, and
  what is engineering debt rather than blocking. Added `AG-TEST-001` (fuzzing), which had been flagged
  in earlier audits as the largest methodological gap but never recorded as a debt item.
- **Kept the release-candidate posture.** No claim of production certification, no suggestion that
  hosted CI is green, and `AG-CI-001` remains open and listed first among the blocking items.

Deliberately not done: no tagging or publication of `0.2.0rc4` (that is a separate explicit step), no
`AG-EVID-001` contract change, no marketing content, and no change to any enforcement behavior.

## CI evidence update — AG-CI-001 narrowed, not closed

The self-hosted runner `agentguard-mac-arm64` (registered on the maintainer's machine, labels
`self-hosted, macOS, ARM64, agentguard-core`) was installed as a launchd service via its own
`./svc.sh install && ./svc.sh start` and came online. The queued PR #32 validation then executed and
failed at the confirmatory runtime preflight, not at any product code.

Cause: `CONFIRMATORY_RUNTIME_IDENTITY.json` freezes the git blob of `pyproject.toml`
(`75e4afcf…`, which contains `version = "0.2.0rc3"`), and the preflight fails closed on drift. Phase 0
(`a4604ec`, exclude research from the distribution) and Phase 3 (`a7b2fea`, cut `0.2.0rc4`) both
changed that file, so the blob is now `c9204147…`. Of the six frozen git objects only
`project_metadata` drifted. The control is working as designed; it is simply mis-scoped as a gate on
product commits, and because PR #30 made this workflow the primary path, every product PR failed
before `make check` could run.

Resolution, approved as workflow scoping only (`49db81d`):

- The preflight step is now conditioned on `research/authorization-lineage-experiment-v1`, verified to
  be the one branch whose `pyproject.toml` matches the freeze. `github.head_ref` is used because
  `github.ref` is `refs/pull/N/merge` on pull_request events.
- The evidence completeness gate no longer asserts the preflight output unconditionally.
- The evidence summary reports `NOT_RUN (research-branch-only gate)` instead of asserting `PASS` for a
  step that did not execute.

`CONFIRMATORY_RUNTIME_IDENTITY.json` is untouched; the preflight is not weakened or made
non-blocking on the research branch.

Result — run `36910522462`, commit `0ec42a29`: **success** in 8m52s, with `make check` at 839 passed /
3 skipped, `pip_audit` pass, MCP security gate pass. Green self-hosted validation evidence now exists for
the `0.2.0rc4` product line.

Re-run after the evidence-wording commit: run `36916055898`, head `6f071ed`: **success** in 7m4s with the
same gate results. It supersedes `36910522462` as the authoritative artifact for this line, because its
evidence reflects the corrected `HOSTED_CI_REPLACED` wording. Both runs are cited in
`docs/project-status.md` and the changelog rather than only the newer one.

`AG-CI-001` is therefore **partially satisfied and remains open**, narrowed to what is still missing:

- no green hosted CI (`ci.yml`, `codeql.yml`, `security.yml` are `workflow_dispatch`-only);
- no cross-platform matrix (macOS / ARM64 / CPython 3.12.10 only; Ubuntu, Windows, 3.11 and 3.13
  unexercised);
- not independent (`TRUST_SCOPE=trusted-owner-same-repository-only`).

Also corrected here: the self-hosted evidence artifact asserted `HOSTED_CI_REPLACED=false`, which PR #30
made untrue — self-hosted validation has been the primary path since that merge. It now reports
`HOSTED_CI_REPLACED=true` with a meaning key, plus explicit `HOSTED_CI_GREEN_ON_THIS_REF=false` and
`CROSS_PLATFORM_MATRIX=false` so the artifact cannot be read as a hosted-green claim.

Run `36910522462` predates this correction, so its retained artifact still contains the old
`HOSTED_CI_REPLACED=false` string. That is now resolved rather than merely noted: run `36916055898` on
head `6f071ed` regenerated the artifact with `HOSTED_CI_REPLACED=true`,
`HOSTED_CI_GREEN_ON_THIS_REF=false`, and `CROSS_PLATFORM_MATRIX=false`. Both runs remain cited so the
superseded one is not mistaken for current evidence.

No product behavior changed. No production certification is claimed: there is still no independent
security review, no soak test, and no pilot.
