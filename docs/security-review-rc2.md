# RC2 two-pass review report

## Scope

The review used the supplied v0.2.0rc1 Git bundle and source export as the baseline. The repository
history was reconstructed locally and the final RC2 branch was reviewed in two separate passes.

## Pass 1 — security, architecture and correctness

Verified findings included:

- raw secret persistence and permissive SQLite mode in the legacy audit path;
- fail-open MCP behavior when a vague tool name had no inventory;
- cross-server inventory/approval collision through a shared source identifier;
- encoded-path and raw-host metadata bypasses;
- YAML duplicate/unknown-field ambiguity;
- output-redaction flag inconsistency;
- approval budget expansion and validity-window drift;
- credential grant validity extending beyond the decision;
- evidence/key/state symlink and permission weaknesses;
- stdout backpressure and server lifecycle deadlock risk;
- local hash-chain truncation blind spot.

Corrections were implemented with adversarial regression tests. No upstream capability was
intentionally removed; v0.1 behavior remains in an explicit compatibility surface.

## Pass 2 — product, market gap, operations and release engineering

The second pass did not treat a green unit suite as sufficient. It reviewed whether the product can
prove its enforcement boundary and generate credible evidence. It added:

- MCP route coverage and parallel direct-bypass detection;
- signed external audit checkpoints;
- signed evidence manifest attestations;
- explicit legacy data sanitization;
- stable server identity exposed in CLI workflows;
- schema drift checking;
- cross-platform CI definitions;
- non-root container packaging and dependency automation;
- precise product boundaries and production promotion gates.

## Residual release blockers

- public CI has not run on the final RC2 commit in this offline build environment;
- Ruff, mypy, Twine and pip-audit could not be installed from the restricted package index, so
  those RC2 checks must execute in GitHub Actions before promotion; wheel/sdist build, metadata
  inspection and installed-wheel smoke did pass locally;
- no independent penetration test or live broker integration was available;
- real-client and real-server interoperability must be repeated against the final artifact;
- no production pilot, soak test or multi-node state implementation exists.

## Verdict

RC2 is a materially hardened, complete source release candidate and a credible basis for a pilot. It
is not a certified production release. Promotion to `v0.2.0` is conditional on the gates documented
in `docs/production-deployment.md`.
