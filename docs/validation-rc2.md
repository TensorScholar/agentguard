# RC2 local validation record

This record applies to the hardened `v0.2.0rc2` source reconstructed from the supplied Git bundle.
It is local evidence, not a substitute for the mandatory GitHub-hosted release workflow.

## Passed locally

- 314 tests passed; one real-MCP smoke was skipped because it requires an opt-in Node/npm fixture.
- Source-only coverage with branch tracing:
  - statements: 85.27% (`3391 / 3977`);
  - branches: 71.23% (`879 / 1234`);
  - combined coverage.py metric: 81.94%.
- Eleven generated JSON schemas matched their source models.
- Architecture boundary, repository secret and static security scans passed.
- `compileall`, `tabnanny`, workflow YAML parsing, Git whitespace validation and import of all 60
  package modules passed.
- A wheel and complete source distribution were built from the working tree.
- Wheel metadata, entry point and `py.typed` contents were inspected.
- The installed-wheel layout ran `--version`, `--help`, `demo` and `evidence-verify` successfully.
- Demo databases, private key, receipts, grants and evidence artifacts were created with owner-only
  permissions; public keys and intentionally public compatibility examples remained readable.
- The deterministic direct-runtime CycloneDX SBOM generator completed successfully.

## Not passed locally

The restricted package registry did not expose Ruff, mypy, Twine or pip-audit. The imported RC1
commit contains passing evidence for those tools, but RC2 changed code and therefore must pass them
again in CI. Docker/Podman was not available, so the non-root Dockerfile was reviewed but not built.
The opt-in real MCP server fixture, cross-platform matrix, external penetration test and production
soak test also remain promotion gates.

## Interpretation

This is a strong release-candidate validation result, not a production certification. The exact
release commit and artifacts must pass `.github/workflows/ci.yml`, `security.yml`, `codeql.yml` and
the deployment-specific controls in `docs/production-deployment.md` before promotion.
