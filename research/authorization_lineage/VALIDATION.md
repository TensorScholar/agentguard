# DEV validation gate

Before component SHAs may be frozen for confirmatory execution, this branch must pass:

- `ruff format --check .`
- `ruff check .`
- strict `mypy` for `agentguard`
- full `pytest` / repository `make check`
- authorization-lineage DEV tests including A0 gap reproduction, A1/B4 conservation, P1 dedup, P3 fencing, and S11 stale-worker fencing
- dependency audit and existing AgentGuard security gates
- an exact-head self-hosted validation run if hosted CI remains unavailable

Passing this gate is engineering evidence only. It does not create confirmatory research evidence.
