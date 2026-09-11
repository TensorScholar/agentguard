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
- create an SSH-signed release tag for source endorsement:
  ```bash
  git config gpg.format ssh
  git config user.signingkey ~/.ssh/id_ed25519
  git tag -s -m "AgentGuard 0.2.0rc3" v0.2.0rc3 5c57bfe6d944cd05d268150277502bb42ca2e198
  ```
  Verify the tag with:
  ```bash
  git -c gpg.ssh.allowedSignersFile=allowed_signers tag -v v0.2.0rc3
  ```

Do not describe the release candidate as production-certified. Production promotion additionally requires deployment-specific threat review, independent penetration/security testing, long-duration soak testing, operational recovery exercises, and a controlled production pilot without unresolved critical findings.

## Cryptographic release authenticity and artifact verification

AgentGuard uses OpenSSH SSHSIG over authenticated checksums to provide maintainer release endorsement and artifact authenticity/integrity without relying on third-party public logs or custom cryptographic signing implementations.

### Security and capability classification

- **SSH-signed Git tag**: `RELEASE_SOURCE_ENDORSEMENT` (binds maintainer identity to source tree).
- **SSHSIG over SHA256SUMS**: `ARTIFACT_AUTHENTICITY_AND_INTEGRITY` (maintainer endorsement of build outputs).
- **Two-pass deterministic build comparison**: `BUILD_REPRODUCIBILITY_EVIDENCE` (proves bit-for-bit repeatability).
- **Independent builder attestation**: `BUILD_PROVENANCE_ATTESTATION=UNRESOLVED`.
  - *GitHub Artifact Attestations*: `PLAN_BLOCKED` (private repository requires GitHub Enterprise Cloud; currently GitHub Free).
  - *Public Sigstore (Fulcio/Rekor)*: `NOT_APPROPRIATE_PRIVACY` (publishes private repository identity/commits to public transparency log).
  - *Private Sigstore Backend*: `NOT_CONFIGURED` (no dedicated private Fulcio/Rekor instance exists).

Do not refer to maintainer signatures as "provenance"; true build provenance requires an attested, unforgeable builder identity.

### Signing operations (Maintainer)

Signing is a direct maintainer operation using standard OpenSSH tooling. No private signing keys are handled by repository scripts or stored in CI.

1. Generate the canonical distribution artifacts, SBOM, and release manifest via the validated build workflow.
2. In the release artifact directory, create `release/SHA256SUMS` covering all distributions, `release/agentguard.cdx.json`, and `release/release-manifest.json`.
3. Sign `release/SHA256SUMS` using `ssh-keygen`:
   ```bash
   ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n agentguard-release-v1 release/SHA256SUMS
   ```
   This generates `release/SHA256SUMS.sig`.

### Independent verification procedure (Consumer / Auditor)

Verification uses standard OpenSSH tooling and the standalone stdlib verification tool `scripts/verify_release.py`.

The verifier does NOT require `agentguard` or third-party cryptographic libraries to be installed.

1. **Establish Trust Anchor**:
   Maintain an independent OpenSSH `allowed_signers` file containing authorized maintainer public keys.
   Format:
   ```text
   <signer-identity> ssh-ed25519 AAAAC3NzaC1lZDI1NTE5... <optional comment>
   ```
   *Never* accept an `allowed_signers` file packaged inside an untrusted release bundle.

2. **Execute Verification**:
   ```bash
   python scripts/verify_release.py \
     --artifact-root ./extracted-artifacts \
     --allowed-signers /path/to/trusted_allowed_signers \
     --signer-identity maintainer@agentguard.dev \
     --namespace agentguard-release-v1 \
     --expected-project agentguard \
     --expected-version 0.2.0rc3 \
     --expected-commit 5c57bfe6d944cd05d268150277502bb42ca2e198
   ```

### Verification guarantees and transitive trust chain

`scripts/verify_release.py` enforces fail-closed checks across the entire artifact hierarchy:

1. **Cryptographic signature check**: Invokes `ssh-keygen -Y verify` against `release/SHA256SUMS` and `release/SHA256SUMS.sig` using the specified namespace and trusted `allowed_signers`.
2. **Safe checksum parsing**: Rejects malformed lines, non-hex SHA-256 digests, path traversal attempts (`..`), absolute paths, backslashes, duplicate file entries, and symlinks.
3. **Distribution file integrity**: Computes actual SHA-256 digests for all files in `release/SHA256SUMS` and verifies exact matches against disk.
4. **Manifest and commit binding**: Parses `release/release-manifest.json` and verifies project name, semantic version, and the full 40-character hex Git commit SHA.
5. **Cross-artifact consistency**: Verifies that every distribution file (`dist/*`) and SBOM (`release/agentguard.cdx.json`) is present in both `release/SHA256SUMS` and `release-manifest.json`, with matching digests and exact file sizes.
6. **Transitive binding**: Because `release/SHA256SUMS` includes `release/release-manifest.json` (which binds the exact commit) and all distributions/SBOMs, authenticating `SHA256SUMS` cryptographically seals the entire release bundle to the verified commit SHA.
