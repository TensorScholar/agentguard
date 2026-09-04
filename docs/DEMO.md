# AgentGuard Interactive Demo: Action Integrity & Attack Prevention

This walkthrough demonstrates the core technical invariant of AgentGuard:

$$\text{Authorized action} == \text{Credentialed action} == \text{Executed action}$$

Modern AI agents fail catastrophically not during intent formation, but at the execution boundary. When an agent interacts with external tools via protocols like MCP (Model Context Protocol), it is vulnerable to **argument mutation**, **credential scope inflation**, **receipt replay**, and **ambiguous external effects**.

AgentGuard acts as a deterministic, fail-closed execution-integrity kernel that intercepts tool calls before side-effects occur.

---

## Scenario: Bounded Financial Operations

An autonomous customer support agent (`prod/support-agent-v3`) processes order returns.
- **MCP Server:** `customer-operations`
- **Tool:** `refund.create`
- **Authorized Operation:** Refund **\$85.00** (`amount_minor: 8500`) for Order `order-1042`.
- **Policy Limit:** Maximum \$100.00 (`amount_minor: 10000`), requires single-use credential, verified user provenance.

---

## 1. Fast-Path: Automated Attack & Verification Suite

Generate the demo fixtures and run the automated execution and attack suite:

```bash
agentguard demo --output .agentguard/demo --force
```

This single command executes 5 sequential operations through the kernel:
1. **Golden Path:** Authorizes and executes the \$85.00 refund within policy limits.
2. **Attack 1 (Argument Mutation):** An adversarial prompt injection attempts to execute with `amount_minor: 85000` (\$850.00).
3. **Attack 2 (Scope Inflation):** The agent attempts to execute using a credential inflated with `payments:admin`.
4. **Attack 3 (Replay Attack):** The agent or network retry attempts to re-execute using the already-consumed decision receipt.
5. **Cryptographic Evidence Packaging:** Hashes all artifacts, records audit events into SQLite, and signs an evidence manifest with an Ed25519 key.

### Inspect the Interception Results

View the machine-verifiable results in `.agentguard/demo/results.json`:

```bash
cat .agentguard/demo/results.json
```

**Expected Output:**
```json
{
  "happy_path": "authorized",
  "argument_mutation": "execution.arguments_digest_mismatch",
  "excessive_scope": "credential.scope_exceeds_decision",
  "replay": "decision_receipt.replayed",
  "audit": [
    true,
    7,
    "226e2386333128a7ac5a83184a414631209b14c2ee05f4ef211168f330ddf38a",
    null
  ]
}
```

Across these demonstrated scenarios, each attack routed through the protected execution path is intercepted with a deterministic, stable reason code before protected external execution dispatch occurs.

---

## 2. Cryptographic Evidence Verification

AgentGuard bundles the normalized intent, signed decision receipt, credential grant, and execution results into an authenticated evidence manifest.

Verify the integrity and Ed25519 signature of the evidence bundle offline:

```bash
agentguard evidence-verify .agentguard/demo/evidence \
  --public-key .agentguard/demo/public.pem \
  --require-signature
```

**Expected Output:**
```json
{
  "ok": true,
  "checked_artifacts": 4,
  "signature_verified": true
}
```

This verifies that:
- The SHA-256 canonical digests of all inputs, receipts, and outputs match the manifest.
- The manifest signature was produced by the trusted decision authority key.
- No artifact in the bundle was altered or detached post-execution.

---

## 3. Step-by-Step Manual Execution Walkthrough

For a deep inspection of how each phase operates independently, run the lifecycle manually:

### Step 3.1: Policy Evaluation & Authorization

Evaluate an untrusted `ActionIntent` against Policy v2:

```bash
agentguard authorize \
  examples/scoped-refund/request.json \
  examples/scoped-refund/policy.yaml \
  --key .agentguard/demo/private.pem \
  --ledger .agentguard/demo/audit.sqlite \
  --output .agentguard/demo/manual-decision.json
```

This derives the canonical SHA-256 digest of the intent, verifies provenance, and outputs a signed `DecisionReceipt` with an embedded `credential_ceiling`.

### Step 3.2: Issue Bounded Credential Grant

Simulate the credential authority binding the decision receipt to a short-lived, scoped credential grant:

```bash
agentguard broker-demo \
  examples/scoped-refund/request.json \
  .agentguard/demo/manual-decision.json \
  --output .agentguard/demo/manual-grant.json
```

*(Note: `broker-demo` is a local contract-test adapter that demonstrates grant signing and ceiling downscoping without external vault dependencies.)*

### Step 3.3: Execution-Time Revalidation & Binding

Execute the protected action against the signed receipt and grant:

```bash
agentguard verify-execution \
  examples/scoped-refund/request.json \
  .agentguard/demo/manual-decision.json \
  examples/scoped-refund/policy.yaml \
  --grant .agentguard/demo/manual-grant.json \
  --public-key .agentguard/demo/public.pem \
  --state .agentguard/demo/audit.sqlite
```

AgentGuard atomically:
1. Re-derives the canonical digest of `request.json` and verifies it matches `manual-decision.json`.
2. Verifies the decision receipt signature.
3. Checks that `manual-grant.json` does not exceed the `credential_ceiling`.
4. Checks the current policy has not changed.
5. Records the decision nonce in SQLite to prevent replay.

---

## 4. MCP Posture & Bypass Detection

In addition to runtime execution integrity, AgentGuard audits client configuration to detect unsafe, direct, or parallel bypass routes around protected MCP adapters.

### Audit Protected Configuration:

```bash
agentguard mcp-posture \
  --config examples/mcp_posture_protected.json \
  --fail-on-bypass
```
*Result: Passes with 0 bypasses identified.*

### Audit Bypass Configuration:

```bash
agentguard mcp-posture \
  --config examples/mcp_posture_bypass.json \
  --fail-on-bypass
```
*Result: Exits non-zero, identifying unmediated direct paths to MCP servers that circumvent the security kernel.*

---

## 5. Preserved v0.1 Compatibility Suite

The `agentguard demo` command also exports legacy v0.1 MCP posture fixtures to `.agentguard/demo/v1-compat/`.

You can inspect and scan these legacy configurations using the preserved v0.1 CLI commands:

```bash
# Scan dangerous legacy MCP configuration
agentguard scan --config .agentguard/demo/v1-compat/dangerous_mcp_config.json --format markdown

# Evaluate CI risk gate
agentguard gate --config .agentguard/demo/v1-compat/dangerous_mcp_config.json --fail-on-risk high
```

