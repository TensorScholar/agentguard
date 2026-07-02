# Contributing

AgentGuard is intentionally narrow: it is a local-first policy and audit layer for AI-agent tool
access. Contributions should strengthen that control point without turning the project into a
generic observability dashboard, LLM router, or hosted platform.

## Development Setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -e ".[dev]"
python -m pytest -q
```

The runtime package should remain dependency-free unless a dependency clearly reduces security risk
or maintenance burden.

## Engineering Rules

- Keep policy behavior deterministic and testable.
- Do not log raw secrets.
- Do not use `shell=True` for process execution.
- Prefer explicit argv, bounded input sizes, and fail-closed errors.
- Add tests for policy, audit, CLI, and MCP proxy behavior touched by a change.
- Keep features local-first until the product has proven real workflow demand.

## Before Opening A Pull Request

Run:

```bash
python -m compileall -q agentguard tests
PYTHONDONTWRITEBYTECODE=1 PYTHONPATH=. python -m pytest -q -p no:cacheprovider tests
python -m agentguard doctor --workdir /tmp
```

For packaging-sensitive changes, also run:

```bash
python -m venv /tmp/agentguard-install-smoke
/tmp/agentguard-install-smoke/bin/python -m pip install .
/tmp/agentguard-install-smoke/bin/agentguard --version
/tmp/agentguard-install-smoke/bin/agentguard doctor --workdir /tmp
```

## Pull Request Standard

Every PR should explain:

- user-facing behavior changed;
- policy or audit implications;
- tests run;
- known limitations or follow-up work.
