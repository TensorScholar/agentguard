# Changelog

## 0.2.0rc4

Three stabilization and delivery passes, plus a packaging and positioning pass. Packaging only — no
enforcement behavior changed in Phase 3.

### CI evidence for 0.2.0rc4

- Green **self-hosted** validation now exists for this line: run `36910522462` on commit `0ec42a29`
  via runner `agentguard-mac-arm64`, where `make check` passed (839 passed, 3 skipped), `pip_audit`
  passed, and the AgentGuard MCP security gate passed.
- `AG-CI-001` is narrowed, **not closed**. Still missing: green hosted CI (`ci.yml`, `codeql.yml`,
  `security.yml` are `workflow_dispatch`-only since PR #30); a cross-platform matrix (evidence is
  macOS / ARM64 / CPython 3.12.10 only); and independence (`TRUST_SCOPE=trusted-owner-same-repository-only`,
  the runner is the maintainer's own machine).
- The self-hosted workflow previously failed every product PR at the confirmatory research preflight,
  which freezes the git blob of `pyproject.toml` and therefore cannot pass once packaging or version
  changes. The step is now scoped to `research/authorization-lineage-experiment-v1`. The research
  identity file is untouched and the preflight is not weakened on that branch.
- The evidence artifact no longer asserts `Confirmatory Runtime Preflight: PASS` for a step that did not
  run, and no longer claims `HOSTED_CI_REPLACED=false`, which PR #30 made untrue.

Still an engineering-validated release candidate: no independent security review, no soak test, no
controlled production pilot.

### Phase 3 - packaging and positioning

- Cut `0.2.0rc4`. Phases 0-2 were verified but sat under an "Unreleased" heading above the shipped
  `0.2.0rc3`, so an installed artifact contained all the Phase 0-2 code while advertising a version
  that previously meant a different tree. `0.2.0rc3` and `0.2.0rc4` are not interchangeable. Version
  metadata, CITATION, and the changelog heading move together.
- **Fix an sdist packaging defect.** `MANIFEST.in` included `examples/` without `*.py`, so an sdist
  consumer received the harness README instructing them to run `run_demo.py` without receiving it.
  The wheel still carries no harness files and `src/agentguard/research` remains excluded from both.
- Add a cold-start evaluation path to the README: install, run the demo, verify evidence and detect
  tampering, then read the credential contract and limitations. Every command in it was executed
  verbatim from a clean virtualenv.
- Add `docs/COLLABORATION.md` (one-page collaboration brief) and `docs/FAQ.md` (talking points).
- Restructure `docs/project-status.md` with a Phase 0-3 delivery history and promotion debt grouped by
  what blocks a pilot, what blocks a credential-path production claim, and what is non-blocking. Add
  `AG-TEST-001` (fuzzing), previously flagged but never recorded as debt.

Still true and still stated up front: engineering-validated release candidate, not production
certified; no independent review, soak test, or pilot; and no green hosted CI run (`AG-CI-001`).

### Phases 0-2

The release remains a release candidate: engineering validated on a single host, not production
certified, and with no green hosted CI run yet (`AG-CI-001`). Phase 0 was stabilization and honesty,
Phase 1 defined the product wedge, Phase 2 made it demable end to end.

### Phase 2 - practical MVP of the wedge

Practical-MVP pass. Every item below closed a gap that made the documented happy path fail for a new
user. Each was found by executing the documented path, not by reading it.

### Fixed: the documented happy path did not work

- **Tool description was discarded before capability classification.** `intent_from_tools_call`
  rebuilt a `{"name", "inputSchema"}` dict for `classify_tool_definition`, and both the HTTP and stdio
  schema caches dropped `description` when building the bound schema. A tool whose capability is only
  inferable from its description classified as `unknown`, which a default-deny `unknown_capability`
  then rejected -- making the strict happy path unusable against most real MCP servers. Fixed in
  `intent.py`, `http_gateway.py`, and `protected.py`. This also strengthens schema binding: declared
  semantics now participate in the schema digest, so a provider cannot silently change a tool's
  meaning without detection.
- **No MCP adapter ever supplied provenance.** All three protected adapters called
  `intent_from_tools_call` without provenance, so every live MCP intent was `(unverified, False)` and
  any policy with `unknown_provenance != allow` refused every call. Added `--provenance` and
  `--provenance-verified` to `mcp-proxy-v2` and `agentguard-mcp-http`, defaulting to `unverified`.
  The parser rejects unknown labels and the contradictory `unverified` + trusted-label mix.
- **`agentguard init` never created the key `agentguard-mcp-http` expects.** The gateway defaults
  `--credential-key` to `.agentguard/credential-broker-private.pem`; `init` only wrote
  `broker-private.pem`. Following the documented setup made the production credential path fail
  immediately. `init` now writes both.
- **Stable reason codes were rendered as Rich tracebacks.** The entrypoint now prints
  `<Type>: <reason_code>` on stderr and exits 2 for `ExecutionGuardError`,
  `EvidenceVerificationError`, `ServiceDeploymentError`, and related denial classes.
- **The gateway swallowed the credential reason code.** It now includes `error.data.reason_code`, for
  example `credential.profile_scope_mismatch`. A missing `--credential-key` file is caught at startup
  with a message naming `agentguard init`.

### Added: runnable demo harness

- `examples/harness/` -- a stdlib-only fake MCP provider with its own durable ledger, a strict
  default-deny demo policy, and a one-command driver. Not installed by `pip`. The provider commits a
  refund then drops the connection, so an ambiguous outcome is real rather than asserted, and its
  `refund.status` tool returns `structuredContent` so the real reconciler can resolve the `UNKNOWN`
  without redispatching.
- `python examples/harness/run_demo.py` runs the whole path in about five seconds: 28 checks, exit 0.
  It proves credential late-resolution with no secret in any durable artifact, argument mutation and
  receipt replay refused with stable codes, an ambiguous effect recorded `UNKNOWN` with
  `retry_safe: false`, provider-verified reconciliation without redispatch, and offline evidence
  verification including tamper detection.
- The harness README states plainly what the demo does NOT prove: the fake provider confirms from its
  own ledger and is not an external attestation, and none of it is a certification, benchmark, or
  penetration test.

### New debt (not claimed as done)

- `AG-EVID-001` -- a reconciliation resolution records no provider operation id. The reconciler
  observes it and folds it into `evidence_digest`, but the contract frozen by ADR 0004 carries only a
  digest, so `provider_operation_id_digest` stays empty. Additive contract change, deliberately
  deferred.
- Provenance on the live MCP path is operator-declared, not inferred. Recorded in `docs/limitations.md`
  as the adapter-as-TCB-boundary assumption it is.
- The capability classifier remains keyword-based and advisory.

### Phase 1 - product wedge

Product-focus pass. No feature was added, no module was deleted, and no behavior changed. The change is
to what the project leads with and what a reader is shown first.

### Product wedge

- Narrow the product thesis to four mechanisms and state it as one paragraph: decision-bound credential
  ceilings with late secret resolution; execution-time digest revalidation with single-use claim;
  durable `ExternalEffectBinding` with `RECONCILE_BEFORE_RETRY`; hash-chained ledger with signed
  evidence bundles and offline verification.
- State six non-goals up front in `docs/limitations.md` and `docs/product-boundary.md`: multi-host/HA,
  identity issuance, generic policy-gateway competition, vault or token minting, isolation/egress
  control, and production certification.
- Add a 5-minute grasp / 30-minute evaluation path to the README, naming who the product is for and
  stating that the core single-use admission-ticket pattern is prior art.
- Collapse the documented happy path to four steps: `authorize`, execute through `mcp-proxy-v2` (or
  `agentguard-mcp-http`), `evidence-build`, `evidence-verify`, with `reconcile-execution` as an
  operator-only branch.
- Demote causal graphs, field provenance and typed releases, policy counterfactuals, delegated
  authority trees, approval receipts, checkpoint signing, attestations, the reconciliation worker, and
  the v0.1 compatibility CLI into an explicit "Advanced Surface" table. Code, tests, and support are
  unchanged; `docs/project-status.md` now splits validated capabilities into product wedge versus
  advanced surface.
- Add `docs/credential-contract.md` documenting the ceiling-to-secret contract precisely, including the
  honest limit that a static secret cannot be attenuated so exact scope equality is required, the
  absence of audience proof and upstream revocation, and that `broker-demo` uses the non-production
  mock broker while the production authority is reachable only via
  `agentguard-mcp-http --credential-env`.
- Add `docs/scenarios.md` with three concrete high-stakes scenarios (bounded refund, irreversible
  delete, external effect that goes `UNKNOWN`), each mapped to the mechanisms it exercises and to the
  existing `examples/` material.
- Record Phase 1 decisions in `docs/PROGRESS_TRACKER.md` and restate the product thesis in Product
  Validation Status without upgrading it from a hypothesis.

### Documentation correction

- The README and `docs/DEMO.md` described `verify-execution` as executing and as recording the decision
  nonce. It is a preflight: it mutates nothing, consumes no nonce, and prints "Execution authority
  verified; nonce not consumed. Use protected execution to claim authority." Both documents now say so,
  and the happy path names the protected proxy as the real execution sink. The bearer-ticket property
  of a `DecisionReceipt` is now also stated in `docs/limitations.md`.

### Phase 0 - stabilization and honesty

Stabilization and honesty pass. No product features were added. Two changes are breaking and are
documented in [the v1 to v2 migration guide](docs/migration-v1-to-v2.md).

### Research honesty

- Add a `Research Status` section to `README.md` above the fold recording
  `RESEARCH_CLAIM: NOT_VALIDATED` and
  `AGENTGUARD_SPECIFIC_DIFFERENTIATION_THESIS: FALSIFIED_WITHIN_PROTOCOL`, the 6.45 slot-hold ratio
  favoring the no-guard baseline, the scope exclusions from
  `docs/research/FREEZE_V2_RESULT_ADJUDICATION.md` §6, and the unestablished product claims.
- State in the README that the core single-use-receipt / digest-revalidation pattern is not unique to
  this project and is specified in external work.

### Breaking: v1 policy default is now deny

- **Breaking change.** `agentguard.policy.load_policy` and the `Policy` dataclass now default
  `default_action` to `deny` instead of `allow`. A v1 policy that relied on the implicit
  allow-by-default must now declare `default_action: allow` explicitly, or (preferred) declare a
  non-empty `allowed_tools` allowlist, which is checked first and denies every tool it does not
  name.
- Update `examples/policy.yaml` and `examples/policy_with_exception.yaml` to carry explicit
  `allowed_tools` allowlists so no unmatched tool is authorized by omission.
- Update the `coding-agent-local` and `ci-agent` policy packs to ship non-empty `allowed_tools`
  allowlists. Unmatched tools are denied by the `tool.allowlist` rule.
- Add `tests/test_example_policies_default_deny.py` asserting that every shipped v1 example policy
  and policy pack denies an unmatched action, that the v1 loader denies when `default_action` is
  absent, and that shipped v2 example policies declare `defaults.effect: deny`.
- The v2 policy path is unchanged: `PolicyDefaults.effect` is `Literal[Effect.DENY]`.

### Execution API safety

- Rename `agentguard.engine.execution.authorize_execution` to `preflight_execution`. The function
  performs validation only and does not consume the decision nonce; the previous name implied
  single-use enforcement it does not perform.
- Keep `authorize_execution` as a deprecated wrapper that emits `DeprecationWarning` and delegates
  to `preflight_execution`.

### Packaging

- Exclude `agentguard.research` from the wheel and sdist. The pre-registered authorization-lineage
  research program is retained in the repository as the research record and is importable from a
  source checkout or editable install, but is not distributed as unreferenced product code.
- Align coverage measurement with the distributed package so the 80% combined statement/branch floor
  is not spent on non-shipped code.

### CI

- Enable CodeQL result upload with `security-events: write` and no `continue-on-error` so a finding
  can fail the check.
- **No green hosted CI run exists on this line.** Workflows are corrected, but hosted CI evidence is
  tracked as `AG-CI-001` and cross-platform CI is no longer listed as a validated capability.

### Supply chain

- Re-enable Dependabot version-update pull requests for pip and GitHub Actions; the pause dates from
  the RC2 demonstration.
- Pin the build backend by hash in `requirements/build-hashed.txt` and build with `--no-isolation` so
  the build does not depend on whatever the index serves. Hash pinning of the platform-specific
  runtime closure is tracked as `AG-SUP-001`.

### Documentation

- Record Phase 0 decisions in `docs/PROGRESS_TRACKER.md` as corrections to existing behavior rather
  than only forward decisions.
- Mark ADR 0003 superseded by ADR 0005 and ADR 0006 §7 superseded by ADR 0007; annotate ADR 0001 with
  the Q02 to Q04-01 supersession and ADR 0002 with the v1 default-deny alignment.

## 0.2.0rc3

### Runtime-integrity and provider boundary

- Add signed execution attestations, append-only reconciliation, delegated authority and consumable
  capability leases, field-level provenance and typed releases, staged high-impact execution,
  declared causal execution graphs, and deterministic least-authority/policy-counterfactual analysis.
- Add the modern protected MCP HTTP profile while preserving the bounded protected stdio profile.
- Freeze provider/external-effect contracts so ambiguous outcomes remain `UNKNOWN` until trusted
  provider reconciliation establishes stronger evidence; blind retry remains forbidden by default.
- Add provider-neutral production credential authority with late secret resolution, exact provider
  binding, durable revocation, and no provider secret in grants or AgentGuard durable state.
- Persist external-effect bindings before side-effecting dispatch and add provider-specific durable
  reconciliation with explicit `PROVIDER_VERIFIED` evidence semantics.
- Add single-host multi-process reconciliation leases with monotonic fencing tokens, crash-safe
  takeover, stale-worker rejection, explicit operator recovery, bounded worker polling, and operational probes.
- Require TLS, Bearer authentication, and an explicit Host allowlist before non-loopback HTTP binding;
  browser-reachable mode additionally requires an explicit Origin allowlist.

### Release hardening

- Move the release-candidate version to `0.2.0rc3` and enforce consistency across package metadata,
  runtime version metadata, citation metadata, and the changelog.
- Validate the fixed `cryptography==50.0.1` runtime profile and remove the temporary
  `PYSEC-2026-3552` dependency-audit ignore after upgrading beyond its fixed version.
- Add reproducible wheel/normalized-sdist checks, deterministic SBOM and release-manifest generation,
  package checksums, base-wheel and HTTP-extra clean-install smoke, and container smoke validation.
- Package the existing protected HTTP service CLI as the `agentguard-mcp-http` console entrypoint and
  exercise it from clean-installed wheels and the release-candidate container.
- Synchronize public architecture, threat, deployment, limitation, project-status, and release
  documentation with the validated Phase 6 boundary while retaining the non-production-certified
  promotion gate.

## 0.2.0rc2

### Security corrections

- Redact secret-bearing keys and token patterns again at the legacy audit persistence boundary.
- Create SQLite ledgers and private keys with owner-only permissions and secure-delete pragmas.
- Add explicit legacy-ledger sanitization and hash-chain rebuilding.
- Fail closed when MCP inventory is unavailable or stale instead of allowing vague tool names.
- Isolate MCP inventory and approval grants with a stable downstream server identity.
- Normalize encoded, Unicode, Windows-style and file-URI paths before sensitive-path matching.
- Normalize raw hosts, URLs, IDNA names, decimal/hex/octal/short IPv4, IPv4-mapped IPv6 and
  link-local metadata destinations.
- Fail closed on excessive nested URL encoding.
- Reject duplicate YAML keys, aliases, unknown policy fields and malformed exception scopes.
- Enforce approval budget ceilings and decision-bound approval validity windows.
- Prevent credential grants from outliving the decision receipt or exposing handles in brokered mode.
- Add symlink-aware, atomic file operations for keys, evidence, CLI output and SQLite state.
- Make both legacy and v2 MCP relays concurrent and bounded to avoid stdout backpressure deadlocks.
- Reject duplicate outstanding JSON-RPC IDs, preserve bidirectional request correlation and invalidate
  cached inventory on `tools/list_changed` or failed refresh.

### Market and operational controls

- Add `mcp-posture` to detect direct, ambiguous, invalid and parallel bypass routes.
- Add signed audit checkpoints for externally anchored truncation/replacement detection.
- Add optional Ed25519 evidence-manifest attestations and signature-required verification.
- Add an immutable generated schema for audit checkpoints and evidence attestations.
- Add non-root Docker packaging, cross-platform CI definitions and Dependabot configuration.
- Add two-pass security/product review, market-gap analysis and production deployment guidance.

## 0.2.0rc1

- Reframed AgentGuard as a provider-neutral action-integrity kernel.
- Added strict ActionIntent and Policy v2 schemas with default deny.
- Added provenance-aware policy, tenant binding and blast-radius budgets.
- Added Ed25519-signed decision receipts and execution-time digest binding.
- Added atomic replay prevention and credential ceiling verification.
- Added a provider-neutral mock credential broker, correlated audit chain and evidence bundles.
- Preserved an MCP stdio enforcement path and added HTTP transport security checks.
