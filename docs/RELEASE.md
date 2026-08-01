# Release checklist

AgentGuard is pre-1.0. A release candidate is promotable only when the exact Git commit passes the
mandatory CI matrix and the generated artifacts can be independently verified.

## Preconditions

- The working tree is clean and the release commit is identified.
- `pyproject.toml`, `agentguard.__version__`, `CITATION.cff` and `CHANGELOG.md` agree.
- Generated JSON schemas match the source models.
- No cache, virtualenv, database, key, audit or demo artifact is tracked.

## Canonical verification

Run from the repository root in an environment created with the validated constraints:

```bash
python -m pip install -c requirements/runtime-validated.txt -e '.[http]'
python -m pip install -r requirements/validation.txt
make check
```

Coverage is measured with branch tracing over `src/agentguard` only. The release gate is a combined
source coverage of at least 80%; statement and branch percentages must also be reported separately.

## Build and clean-install smoke

```bash
rm -rf build dist *.egg-info src/*.egg-info
SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)" python -m build
python -m twine check dist/*
python -m venv /tmp/agentguard-install-smoke
/tmp/agentguard-install-smoke/bin/python -m pip install dist/*.whl
/tmp/agentguard-install-smoke/bin/agentguard --version
/tmp/agentguard-install-smoke/bin/agentguard --help >/dev/null
/tmp/agentguard-install-smoke/bin/agentguard demo --output /tmp/agentguard-demo
/tmp/agentguard-install-smoke/bin/agentguard evidence-verify /tmp/agentguard-demo/evidence
/tmp/agentguard-install-smoke/bin/python -m pip check
```

## Security and compatibility gates

- Linux quality matrix: Python 3.11, 3.12 and 3.13.
- Compatibility smoke: Linux, macOS and Windows on Python 3.13.
- CodeQL, dependency audit, architecture boundary check, repository secret scan and static security
  scan.
- Real MCP smoke remains opt-in locally but should run in a controlled release environment. The
  compatibility fixture is pinned to `@modelcontextprotocol/server-filesystem@2026.1.14` and must
  not be silently upgraded during a release.
- Signed evidence, audit checkpoint, MCP posture and fail-closed inventory scenarios must pass.

## Promotion boundary

Do not describe a release candidate as production-certified. Promotion requires the CI run for the
release commit, a deployment-specific threat review, external penetration testing and a controlled
production pilot.
