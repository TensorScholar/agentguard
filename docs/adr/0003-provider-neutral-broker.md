# ADR 0003: Provider-neutral credential broker

The domain depends on a provider-neutral `CredentialBroker` port. External credential providers may be implemented as adapters, but the RC contains only a mock broker and no vendor-specific integration.
