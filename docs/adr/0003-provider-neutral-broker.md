# ADR 0003: Provider-neutral credential broker

The domain depends on a `CredentialBroker` port. Loadout, Vault or another provider is implemented as an adapter. The RC contains only a mock broker and a non-networking Loadout contract preview because a real API contract was unavailable.
