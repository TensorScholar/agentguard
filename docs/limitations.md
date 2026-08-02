# Limitations

- AgentGuard enforces only traffic routed through an AgentGuard adapter. `mcp-posture` detects direct
  routes in supplied configurations but cannot prove the absence of hidden, generated or network-level
  bypass paths.
- The v2 MCP processor requires a trusted, fresh schema resolver. Without one, `tools/call` fails
  closed with approval required.
- The HTTP module provides validation primitives, not a complete production Streamable HTTP proxy.
- Provenance and verified identity are only as trustworthy as the adapter that supplies them.
- Effect projection is adapter-supplied; ambiguous high-impact effects must never be projected as zero.
- SQLite replay, approval and issuance semantics are single-node. Multi-replica deployment requires
  a shared transactional repository.
- Canonical JSON supports the signed schema subset and rejects floats; this RC does not claim full
  RFC 8785 behavior for arbitrary JSON numbers.
- Signed audit checkpoints detect retained-prefix mismatch only when exported to independently
  controlled storage. Keeping the checkpoint beside the database adds little protection.
- Evidence signature verification authenticates the manifest key, not the business truth of the
  underlying event or the identity proofing process behind the signer.
- The mock broker and Loadout adapter are contract previews, not live production integrations.
- Interactive, identity-backed human approval UX is not included.
- No external penetration test, long-duration soak test or production pilot has been completed.
- AgentGuard applies owner-only file modes on POSIX systems. On Windows, sensitive files inherit
  NTFS ACLs from their containing directory; exact ACL hardening and verification require
  deployment-level ACL configuration. AgentGuard does not claim that POSIX `0600` semantics can be
  proven through `st_mode` on Windows.
- RC2 changes were locally exercised on Linux/Python 3.13. Cross-platform jobs are defined in CI but
  must run on the final Git commit before release promotion.
- Legacy Policy v1 retains compatibility-oriented semantics, including an allow default for ordinary
  known calls; production deployments should prefer Policy v2 and explicit allow rules.
