# Contributing

DecisionLock is security-sensitive software. Small changes can alter authorization, replay, credential, and audit semantics.

## Development setup

Use Python 3.11 or newer.

```bash
python -m venv .venv
. .venv/bin/activate
python -m pip install -e '.[dev]'
make check
```

`make check` is the minimum local gate before opening a pull request.

## Pull-request requirements

A pull request must:

- describe the security or operational behavior being changed;
- remain narrowly scoped;
- include tests for the changed behavior;
- preserve deterministic reason codes and fail-closed behavior;
- update schemas and documentation when public contracts change;
- avoid unrelated formatting, refactoring, or dependency churn;
- pass the exact GitHub Actions checks for its final head commit.

Security-sensitive changes should test applicable allow, deny, approval, replay, mutation, stale-state, concurrency, and failure paths.

## Architecture rules

- Domain and policy code must remain independent of transport, CLI, database, telemetry, and provider SDKs.
- External systems must connect through typed ports and adapters.
- An adapter must not silently weaken policy, credential ceilings, replay protection, or audit guarantees.
- Provider-specific work requires an explicit, separately reviewed scope and must not become a core dependency.

## Reporting vulnerabilities

Do not open a public issue for a vulnerability. Follow [SECURITY.md](SECURITY.md).
