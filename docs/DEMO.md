# AgentGuard Demo

This demo shows the core product claim:

> AgentGuard detects risky AI-agent tool access, blocks dangerous calls before execution, and
> leaves audit evidence.

## Generate Demo Files

```bash
python -m agentguard.cli demo --output .agentguard/demo --force
```

The generated directory contains:

- `policy.yaml`
- `safe_mcp_config.json`
- `dangerous_mcp_config.json`
- `tool_calls.jsonl`
- `README.md`

## Scan Safe Config

```bash
python -m agentguard.cli scan \
  --config .agentguard/demo/safe_mcp_config.json \
  --format markdown
```

Expected result: below the default CI gate threshold.

## Scan Dangerous Config

```bash
python -m agentguard.cli scan \
  --config .agentguard/demo/dangerous_mcp_config.json \
  --format markdown
```

Expected result: critical risk because the config exposes credential-like environment variables,
cloud deployment tooling, shell execution, and metadata-service network access.

## Run CI Gate

```bash
python -m agentguard.cli gate \
  --config .agentguard/demo/dangerous_mcp_config.json \
  --fail-on-risk high
```

Expected result: non-zero exit with a clear gate failure message.

## Run Policy Proxy

```bash
python -m agentguard.cli proxy \
  --policy .agentguard/demo/policy.yaml \
  --ledger .agentguard/demo/audit.sqlite \
  < .agentguard/demo/tool_calls.jsonl
```

Expected result:

- `.env` read is denied.
- `run_command` requires approval.
- `README.md` read is allowed.

## Render Audit Evidence

```bash
python -m agentguard.cli report \
  --ledger .agentguard/demo/audit.sqlite \
  --format markdown
```

Verify the audit ledger hash chain:

```bash
python -m agentguard.cli verify-audit \
  --ledger .agentguard/demo/audit.sqlite
```

This produces the local audit evidence a team can attach to a review, incident, or security
assessment.
