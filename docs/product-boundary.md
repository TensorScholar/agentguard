# Product Boundary & Architecture

AgentGuard is the **Runtime Action Integrity Layer** situated between an AI agent runtime and a tool executor.

This document formalizes the boundary separating AgentGuard from adjacent systems across the modern enterprise AI stack. AgentGuard operates cooperatively with these systems across distinct architectural domains, rather than replacing them.

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
│  • Credential ceiling enforcement & late secret resolution             │
│  • Execution-time digest revalidation (blocks argument mutation)       │
│  • Atomic nonce consumption (blocks receipt replay & double spend)     │
│  • Durable external-effect binding & RECONCILE_BEFORE_RETRY contracts  │
│  • Single-host multi-process reconciliation leasing & fencing tokens   │
│  • Secret-minimized hash-chained audit & signed evidence bundles       │
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

### 5. Operating System & Network Infrastructure vs. AgentGuard
- **Infrastructure Sandboxing (e.g., Containers, gVisor, eBPF, Firecracker, Linux MAC):** Owns process isolation, memory safety, CPU limits, and network egress firewalls.
- **AgentGuard:** Operates within user space as an application/service-level integrity layer. It relies on deployment infrastructure for host-level isolation, filesystem permissions (`0600`), and secure network routing.

### 6. Observability & SIEM vs. AgentGuard
- **SIEM & Centralized Logging (e.g., Splunk, Datadog, OpenTelemetry):** Long-term multi-system event correlation, visualization, and organization-wide alerting.
- **AgentGuard:** Generates a local, tamper-evident, hash-chained ledger and portable signed evidence bundles. Exported checkpoints can be forwarded to independently controlled external storage or SIEMs for tamper detection.

