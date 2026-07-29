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
