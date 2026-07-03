# Release Checklist

AgentGuard is pre-1.0. This checklist keeps releases boring, reproducible, and auditable.

## Preconditions

- Working tree is clean.
- `CHANGELOG.md` has the intended release notes.
- `pyproject.toml` version matches `agentguard.__version__`.
- No demo, audit, cache, or virtualenv artifacts are staged.

## Verification

Run from the repository root:

```bash
python -m compileall -q agentguard tests
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python -m pytest -q -p no:cacheprovider tests
PYTHONPATH=. python -m agentguard --version
PYTHONPATH=. python -m agentguard doctor --workdir /tmp
PYTHONPATH=. python -m agentguard gate \
  --config examples/dangerous_mcp_config.json \
  --format findings-json \
  --output /tmp/agentguard-findings.json \
  --summary-output /tmp/agentguard-summary.md \
  --fail-on-risk high
```

The final gate command should fail because the dangerous demo config is intentionally critical.

Optional real MCP compatibility smoke:

```bash
AGENTGUARD_RUN_REAL_MCP_SMOKE=1 \
PYTHONDONTWRITEBYTECODE=1 \
PYTHONPATH=. \
python -m pytest -q -p no:cacheprovider tests/test_mcp_real_server_smoke.py
```

This installs pinned `@modelcontextprotocol/server-filesystem@2026.1.14` into a temporary npm
prefix and verifies AgentGuard can capture real `tools/list` inventory, allow a read-only tool
call, and block a write-capable tool call. It requires Node.js and npm and is intentionally opt-in.

## Install Smoke

```bash
python -m venv /tmp/agentguard-install-smoke
/tmp/agentguard-install-smoke/bin/python -m pip install .
/tmp/agentguard-install-smoke/bin/agentguard --version
/tmp/agentguard-install-smoke/bin/python -m agentguard --version
/tmp/agentguard-install-smoke/bin/agentguard doctor --workdir /tmp
```

## Tagging

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

Do not tag if any verification command fails unexpectedly.
