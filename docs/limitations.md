# Limitations

- Local SQLite nonce semantics are single-node, not distributed.
- Canonical JSON supports the signed schema subset and rejects floats; it is JCS-oriented but this RC does not claim complete RFC 8785 implementation for arbitrary JSON numbers.
- The HTTP module contains security validation primitives, not a full production reverse proxy.
- Provenance is only as trustworthy as the adapter that assigns it.
- Effect projection is supplied by a trusted adapter; ambiguous high-impact effects must not be treated as zero.
- The Loadout adapter is a contract preview, not a live integration.
- Approval receipt persistence and interactive approval UX are reserved for the next hardening increment.
- Local hash chaining detects modification of retained audit events but cannot prove tail
  non-truncation without an externally anchored head.
- Existing v0.1 SQLite audit files are retained as evidence and rejected by the v0.2 state adapter;
  an in-place data migration is intentionally not provided in this release candidate.
