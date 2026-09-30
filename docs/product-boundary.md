# Product Boundary & Architecture

AgentGuard is a **decision-bound credential and execution-evidence layer** for high-stakes MCP tool
calls. It sits between an agent runtime and a tool executor and does four things: it bounds the
credential to the authorization, revalidates the authorization against the bytes actually dispatched,
binds the external effect before it happens, and produces evidence a third party can verify offline.

> **Product thesis.** AgentGuard protects high-stakes MCP tool calls by binding a short-lived,
> decision-scoped credential ceiling to a signed authorization, resolving the actual secret only at the
> last moment, preventing replay and argument mutation, and producing independently verifiable evidence
> of what was authorized versus what was observed — especially for actions that can leave ambiguous
> external effects.

This document formalizes the boundary separating AgentGuard from adjacent systems. AgentGuard operates
cooperatively with them across distinct domains rather than replacing them.

## What this release line leads with

| Mechanism | Boundary it draws |
|---|---|
| Decision-bound credential ceilings + late secret resolution | Between *what the agent may call* and *what secret it holds* |
| Execution-time digest revalidation + single-use claim | Between *what was authorized* and *what is dispatched* |
| Durable `ExternalEffectBinding` + `RECONCILE_BEFORE_RETRY` | Between *an attempt* and *a committed external effect* |
| Hash-chained ledger + signed evidence bundles | Between *what happened* and *what can be proven* |

Everything else the codebase implements — causal execution graphs, field provenance and typed releases,
policy counterfactuals, delegated authority trees, approval receipts, checkpoint signing, the
background reconciliation worker, the preserved v0.1 CLI — is **advanced surface**. It is retained and
supported. It is not the product and no claim here depends on it. See the README's
[Advanced Surface](../README.md#advanced-surface-not-part-of-the-wedge).

## Explicit non-goals for this release line

Not roadmap items; boundaries:

- **Multi-host, HA, or distributed consensus.** Single-host multi-process over local SQLite only.
- **Issuing or verifying identity.** AgentGuard binds identity a trusted integration supplies.
- **Generic policy-gateway competition.** No policy authoring, simulation, or content filtering.
- **Secret storage or token minting.** One environment variable, read at dispatch, never persisted.
- **Process isolation, filesystem MAC, or network egress control.**
- **Production certification.** No independent penetration test, soak test, or pilot has completed.

---

## Architectural Context: Separation of Concerns

```text
┌────────────────────────────────────────────────────────────────────────┐
│  Agent Frameworks & Orchestrators (e.g., LangChain, AutoGen, CrewAI)   │
│  Function: Intent formation, reasoning loops, task planning.           │
└────────────────────────────────────────────────────────────────────────┘
                                    │  [Untrusted Tool Call Proposal]
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Prompt Safety & Content Filters (e.g., Llama Guard, NeMo Guardrails)  │
│  Function: Natural language filtering, prompt injection detection.     │
└────────────────────────────────────────────────────────────────────────┘
                                    │  [Filtered Natural Language Proposal]
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Workload & Caller Identity (e.g., OIDC, SPIFFE, mTLS)                 │
│  Function: Cryptographic machine identity & caller authentication.    │
└────────────────────────────────────────────────────────────────────────┘
                                    │  [Authenticated Principal Context]
                                    ▼
==========================================================================
│  RUNTIME ACTION INTEGRITY LAYER (AgentGuard)                           │
│                                                                        │
│  • Normalizes proposed calls into versioned ActionIntent schemas       │
│  • Deterministic Policy v2 evaluation (default-deny, blast-radius)     │
│  • Cryptographic DecisionReceipt issuance (Ed25519 canonical hashing) │
│                                                                        │
│  Primary — the wedge this release line leads with:                     │
│  • Credential ceiling enforcement & late secret resolution             │
│  • Execution-time digest revalidation (blocks argument mutation)       │
│  • Atomic nonce consumption (blocks receipt replay & double spend)     │
│  • Durable external-effect binding & RECONCILE_BEFORE_RETRY contracts  │
│  • Secret-minimized hash-chained ledger & offline-verifiable evidence  │
│                                                                        │
│  Advanced surface — retained, supported, NOT the product:               │
│  • Declared causal execution graphs                                    │
│  • Field provenance & typed-release lifecycle                          │
│  • Policy counterfactual / least-authority analysis (advisory only)   │
│  • Delegated authority grants, leases, delegation trees                │
│  • Approval receipts (no identity-backed approval UX is bundled)       │
│  • Signed checkpoints & execution attestations                         │
│  • Single-host multi-process reconciliation leases & fencing tokens   │
==========================================================================
                                    │  [Verified, Bounded Dispatch]
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Enterprise Secret & Key Management (e.g., HashiCorp Vault, AWS, KMS)  │
│  Function: Long-term secret storage, rotation, and hardware signing.   │
└────────────────────────────────────────────────────────────────────────┘
                                    │  [Late-Injected Credentials]
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Tool Transports & Providers (e.g., MCP Stdio/HTTP, REST APIs)         │
│  Function: Execution of external business logic and database writes.   │
└────────────────────────────────────────────────────────────────────────┘
                                    │  [Execution Telemetry]
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│  Observability, SIEM & Telemetry (e.g., Splunk, Datadog, OpenTelemetry)│
│  Function: Long-term log aggregation, alert correlation, dashboards.  │
└────────────────────────────────────────────────────────────────────────┘
```

---

## Detailed Boundary Specifications

### 1. Agent Frameworks & Orchestrators vs. AgentGuard
- **Agent Frameworks (e.g., LangChain, AutoGen, CrewAI):** Own cognitive architecture, prompt engineering, context management, and deciding *which* tool to call.
- **AgentGuard:** Treats the agent runtime as an **untrusted proposal source** (independent of any specific framework). It does not participate in model evaluation or planning; it deterministically governs whether a proposed action is authorized, credentialed, and untampered before execution.

### 2. Prompt-Level Safety vs. AgentGuard
- **Prompt Safety (e.g., Llama Guard, NeMo Guardrails):** Evaluates natural language text, detecting toxicity, prompt injections, or conversational jailbreak patterns.
- **AgentGuard:** Operates on **structured execution contracts** at the transport and API boundary. It does not inspect natural language conversation semantics; it enforces deterministic schema bounds, cryptographic parameter digests, credential downscoping, and replay prevention.

### 3. Workload Identity vs. AgentGuard
- **Identity Systems (e.g., SPIFFE, OIDC, IAM):** Issue cryptographic assertions verifying *who* or *what service* is calling.
- **AgentGuard:** Consumes verified identity tokens through protocol adapters and binds them into normalized `ActionIntent` principals. AgentGuard does not issue root identity proofs; it enforces policy constraints conditioned on those verified identities.

### 4. Secret Management vs. AgentGuard
- **Secret Vaults (e.g., HashiCorp Vault, AWS Secrets Manager, KMS):** Own enterprise secret storage, key rotation, and hardware-backed isolation.
- **AgentGuard:** Enforces **credential ceilings** and late secret resolution. It ensures that a credential request matches the signed authorization decision, resolves the secret late via provider-neutral adapters immediately prior to execution, and ensures raw secrets never touch durable decision receipts, external bindings, or audit ledgers.
- **Explicit limit:** the current source is one environment variable. Because a static secret cannot be attenuated, AgentGuard requires the requested scope set to **exactly** equal the configured profile's scopes rather than claiming least privilege it cannot enforce at the provider (`adapters/broker/production.py:250-252`). No token minting, no vault, no rotation. See [Credential Contract](credential-contract.md#what-is-still-missing).

### 5. Operating System & Network Infrastructure vs. AgentGuard
- **Infrastructure Sandboxing (e.g., Containers, gVisor, eBPF, Firecracker, Linux MAC):** Owns process isolation, memory safety, CPU limits, and network egress firewalls.
- **AgentGuard:** Operates within user space as an application/service-level integrity layer. It relies on deployment infrastructure for host-level isolation, filesystem permissions (`0600`), and secure network routing. AgentGuard does not provide isolation and does not close alternate-path bypasses.

### 6. Observability & SIEM vs. AgentGuard
- **SIEM & Centralized Logging (e.g., Splunk, Datadog, OpenTelemetry):** Long-term multi-system event correlation, visualization, and organization-wide alerting.
- **AgentGuard:** Generates a local, tamper-evident, hash-chained ledger and portable verifiable evidence bundles (with optional cryptographic attestations). Exported checkpoints can be forwarded to independently controlled external storage or SIEMs for tamper detection.

