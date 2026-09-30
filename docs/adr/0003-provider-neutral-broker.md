# ADR 0003: Provider-neutral credential broker

**Status: Superseded by [ADR 0005](0005-production-credential-authority.md).**

Superseded because the statement below — "the RC contains only a mock broker and no vendor-specific
integration" — no longer describes the release candidate. ADR 0005 added the production credential
authority profile with late environment-backed secret resolution and exact provider binding. The
provider-neutral `CredentialBroker` port decision itself still stands; what is superseded is the
description of what the RC ships. Note that the mock broker remains a shipped adapter and, per
`docs/limitations.md`, must not be represented as a production credential provider.

The domain depends on a provider-neutral `CredentialBroker` port. External credential providers may be implemented as adapters, but the RC contains only a mock broker and no vendor-specific integration.
