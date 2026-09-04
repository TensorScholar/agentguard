# Release process

AgentGuard releases are evidence-bound to an exact Git commit. A green development branch does not transfer validation to a later squash/tag unless the required gates run again on the exact final SHA.

## Canonical sequence

1. Identify the intended release commit and verify the branch/tree is clean and immutable for the validation window.
2. Run `scripts/check_release_metadata.py` and require `pyproject.toml`, runtime version, `CITATION.cff`, and the top changelog release to agree.
3. Regenerate schemas in check mode and reject unexpected drift.
4. Run Ruff formatting/lint, strict mypy, the complete pytest suite with branch-traced coverage, architecture checks, secret scan, static security scan, and compileall.
5. Run Linux quality on Python 3.11/3.12/3.13 and compatibility tests on Linux/macOS/Windows Python 3.13.
6. Run the Security workflow, including dependency audit **without release-specific ignored vulnerabilities**, plus CodeQL and retain the SARIF artifact/digest.
7. Set `SOURCE_DATE_EPOCH` from the release commit timestamp and build wheel/sdist twice.
8. Require the two wheels to be byte-identical; normalize both sdists with the same epoch and require the normalized archives to be byte-identical.
9. Run `twine check` on the retained distributions.
10. Generate the deterministic CycloneDX SBOM, release manifest bound to the exact commit, and SHA-256 checksum file.
11. Install the base wheel in a clean virtual environment and smoke the core CLI, reconciliation entrypoints, demo, evidence verification, and `pip check`.
12. Install the wheel with the `http` extra in a separate clean environment and smoke `agentguard-mcp-http`, reconciliation entrypoints, HTTP module import, and `pip check`.
13. Build the container, prove it runs as the non-root runtime UID, smoke the core CLI, and prove the HTTP dependencies/service entrypoint are installed.
14. Preserve the release-candidate distributions and release evidence as workflow artifacts.
15. Run controlled real-MCP interoperability/failure tests for the deployment-supported profiles; keep protocol/server versions pinned in the evidence.
16. Verify hashes and exact-SHA workflow results before creating the release tag.
17. Prefer a signed/attested release tag and artifact provenance when the release environment supports them; do not infer signing from an unsigned commit or lightweight phase tag.
18. Do not call a release production-certified until independent security review, long-duration soak testing, and a controlled production pilot have passed.

## Coverage reporting

Coverage uses branch tracing over `src/agentguard` and enforces a combined source threshold of at least 80%. Release evidence should report statement, branch, and combined values distinctly; the combined metric must not be mislabeled as branch coverage.

## Reproducibility boundary

Wheel byte identity is checked directly. Source distributions are normalized before comparison because archive metadata can otherwise vary despite identical source payloads. Normalization requires an explicit `SOURCE_DATE_EPOCH`; a hidden hard-coded release timestamp is not permitted.

Reproducible build checks establish artifact determinism for the validated environment. They are not a substitute for signing, provenance attestation, dependency trust, or independent artifact verification.
