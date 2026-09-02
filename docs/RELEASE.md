# Release checklist

AgentGuard is pre-1.0. A release candidate is promotable only when the exact Git commit passes the mandatory CI/Security/CodeQL gates and the generated artifacts can be independently verified.

## Preconditions

- The release branch points at the intended exact commit and no uncommitted/local-only content is part of the release decision.
- `pyproject.toml`, `agentguard.__version__`, `CITATION.cff`, and the top `CHANGELOG.md` release agree.
- README/deployment documentation refers to the current release candidate rather than an earlier version.
- Generated JSON schemas match the source models.
- No cache, virtualenv, database, key, audit, demo output, or secret artifact is tracked.
- Temporary dependency-audit exceptions are absent unless a current, documented, narrowly scoped exception has explicit removal criteria.

## Canonical quality verification

From the repository root in the validated environment:

```bash
python -m pip install -c requirements/runtime-validated.txt -e '.[http]'
python -m pip install -r requirements/validation.txt
make check
```

The quality matrix runs this on Linux Python 3.11, 3.12, and 3.13. Compatibility tests run on Linux, macOS, and Windows Python 3.13.

Coverage is branch-traced over `src/agentguard`; the enforced combined source threshold is at least 80%. Statement, branch, and combined percentages must be reported distinctly in release evidence.

## Package and reproducibility gate

The CI package job is canonical. It:

1. derives `SOURCE_DATE_EPOCH` from the exact commit;
2. builds wheel/sdist twice;
3. byte-compares the wheels;
4. normalizes both sdists with that epoch and compares them;
5. runs `twine check`;
6. generates `agentguard.cdx.json`, `release-manifest.json`, and `SHA256SUMS`;
7. clean-installs the base wheel and exercises the core/reconciliation CLIs plus demo/evidence verification;
8. clean-installs the wheel with `[http]` and exercises `agentguard-mcp-http` plus reconciliation entrypoints;
9. builds the non-root container and smokes the installed package/HTTP dependencies;
10. uploads the distributions and release evidence as the `agentguard-release-candidate` workflow artifact.

Do not replace this with a local build and assume equivalence; retain the workflow evidence for the exact release SHA.

## Security gates

- Architecture boundary, repository secret scan, static security scan, and dependency audit must pass.
- Dependency audit must not silently ignore a vulnerability merely because a previous release line documented an exception.
- CodeQL must pass and its SARIF artifact/digest should be retained in the release evidence.
- Signing keys, credential material, and generated private state must not appear in release artifacts.

## Interoperability gates

- The real MCP smoke remains controlled/opt-in because it invokes external tooling, but the release environment should run the profiles claimed by the release.
- The preserved filesystem compatibility fixture is pinned to `@modelcontextprotocol/server-filesystem@2026.1.14`; do not silently change that pin during release validation.
- Deployment-specific `mcp-posture --fail-on-bypass` must pass for the configurations being promoted.

## Tag and promotion boundary

Before tagging:

- verify CI, Security, and CodeQL are all bound to the exact release commit;
- verify release-manifest commit/version and SHA-256 hashes;
- verify the final release tree is the one that passed the gates;
- prefer a signed/attested release tag when available.

Do not describe the release candidate as production-certified. Production promotion additionally requires deployment-specific threat review, independent penetration/security testing, long-duration soak testing, operational recovery exercises, and a controlled production pilot without unresolved critical findings.
