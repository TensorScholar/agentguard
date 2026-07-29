# Architecture

AgentGuard is a modular monolith using ports and adapters. The domain and engine are deterministic and have no dependency on SQLite, HTTP, MCP, Typer, OpenTelemetry or any credential provider.

```text
Protocol adapter -> ActionIntent -> Policy engine -> DecisionReceipt
                                        |                |
                                        v                v
                                  approval path    CredentialBroker
                                                         |
                                                         v
                                                 ExecutionGuard
                                                         |
                                                         v
                                                   Audit evidence
```

The package follows a functional-core/imperative-shell split. All security decisions are explainable through stable reason codes. External systems are connected only through typed ports.

Credential issuance is claimed atomically before a broker is invoked. A single-use decision keeps
that claim even when the broker fails, so an outage cannot turn into an unbounded retry channel.
Multi-use decisions may retry with a new credential request while the decision remains valid, but
each attempt consumes one approval use when approval is required. Execution nonce consumption is a
separate transaction and is never used as a substitute for issuance consumption.

Broker grants carry a provider-neutral Ed25519 attestation in the mock adapter. The authenticated
payload binds the broker and key identity, decision and trace, issuance identifier, audience,
scopes, tenant, mode, timestamps, and a digest of the opaque handle. Production adapters may use a
different authentication mechanism only through an explicit trusted `BrokerGrantVerifier` port.

The v2 MCP adapter obtains each `tools/call` schema through a `ToolSchemaResolver`. The included
resolver projects the preserved v0.1 discovered inventory into the v2 path. Missing, stale, or
digest-inconsistent schemas require approval before authorization; the adapter never substitutes an
empty schema for an allowed call.
