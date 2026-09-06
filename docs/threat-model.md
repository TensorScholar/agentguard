# Threat Model

## Protected properties

AgentGuard is designed to preserve the following properties on traffic that actually crosses a protected adapter:

- the executed action must match the signed authorization decision;
- approval, delegated authority, typed releases, and capability leases must not expand their signed bounds;
- credential material must stay inside the approved provider/audience/scope/tenant/lifetime boundary;
- provider secrets must not be persisted in decision grants, external-effect bindings, audit, or execution evidence;
- receipts, approvals, leases, typed releases, and execution permits must not be replayed beyond their allowed use;
- a protected execution must not begin side effects after its authorization has expired;
- protected MCP calls must fail closed when current schema/inventory/security context cannot be trusted;
- a non-loopback HTTP listener must not start without the required TLS/authentication/Host controls;
- a potentially committed external effect must remain ambiguous until stronger reconciliation evidence is obtained;
- an expired or superseded reconciliation worker must not commit authoritative resolution state;
- raw credentials and common secret values must not enter AgentGuard-owned retained audit/evidence artifacts;
- audit truncation/replacement must be detectable when signed checkpoints are retained independently;
- evidence authenticity must be verifiable when the corresponding trusted public key/provider verification contract is available.

## Primary threats

The threat set includes argument/action substitution, confused deputy behavior, cross-tenant reuse, receipt/approval/lease replay, credential inflation, stale or poisoned tool inventory, provider endpoint substitution, direct-route MCP bypass, ambiguous external-effect replay, duplicate reconciliation workers, stale-worker commits after lease expiry, host/origin confusion, unauthenticated remote HTTP exposure, metadata-service SSRF, path/URL normalization bypass, symlink races, stdout/backpressure denial of service, audit modification/truncation/replacement, evidence substitution, and broker/credential-source outage bypass.

## Trust boundaries

1. **Agent/model/client process** — untrusted proposal source.
2. **Protocol adapter** — trusted to parse the supported protocol subset, derive exact action identity, and route protected calls through authorization.
3. **Action-integrity kernel** — trusted deterministic policy, receipt, authority, execution, and reconciliation checks.
4. **Signer/verifier roots** — trusted key boundary; private signing material should remain outside model/tool control.
5. **Credential authority/source** — trusted to resolve only the configured secret/profile and to preserve provider binding.
6. **Provider executor/transport** — trusted to send the exact verified effect to the bound provider endpoint.
7. **Provider reconciler** — trusted only to the assurance level it is configured to emit; `PROVIDER_VERIFIED` requires an independently trusted provider verification contract.
8. **SQLite state** — trusted local transactional/durability boundary for replay, reservations, execution state, and single-host lease fencing.
9. **Independent checkpoint store** — required to detect complete local-ledger replacement/truncation beyond the retained anchor.
10. **Operating system/network** — outside AgentGuard's control; deployment controls must provide process, filesystem, secret, and egress isolation.

## Explicit assumptions

- Protected traffic actually enters an AgentGuard adapter; hidden alternate routes cannot be ruled out by the library alone.
- The adapter labels identity/provenance/provider binding accurately and does not substitute a different operation after verification.
- Private signing keys and provider secret material are inaccessible to the model and untrusted tools.
- The environment-backed credential source is populated by a deployment mechanism appropriate to the environment; AgentGuard is not the secret vault.
- SQLite coordination participants run on one host against the same local filesystem database with ordinary SQLite locking/durability semantics.
- Provider evidence classified `PROVIDER_VERIFIED` comes only from a reconciler whose provider truth-check contract is independently trusted.
- `mcp-posture` receives every configuration artifact the operator expects it to inspect.
- Signed checkpoints are exported to storage an attacker controlling the local ledger cannot rewrite.
- Public verification keys are distributed through an independently trusted channel.
- A decision receipt is a bearer admission ticket inside its validity window: it binds principal claims, not a holder key, so receipt/grant/approval material must be handled as sensitive until consumed, and preflight success is point-in-time only.

## Important adversarial cases

### Ambiguous provider commit

A transport failure after a side-effecting write may mean the provider committed the operation even though AgentGuard did not receive a response. The execution remains `UNKNOWN`; blind retry is forbidden unless the provider contract proves replay safety. Reconciliation is required before retry under the default policy.

### Worker pause beyond lease expiry

A worker may pause after reading provider state, lose its lease, and resume after another worker takes over. The newer worker receives a higher fencing token. The stale worker cannot commit authoritative resolution because the lease owner/token/expiry are revalidated atomically with the write.

### Remote HTTP exposure

Binding the service to a non-loopback interface increases the attack surface. Startup is fail-closed unless TLS certificate/key, Bearer token, and explicit non-wildcard Host allowlist are configured. Browser-reachable Origin enforcement requires an explicit Origin allowlist.

### Evidence forgery versus business truth

A valid AgentGuard signature proves that AgentGuard signed the recorded canonical evidence. It does not prove an unsigned provider's external business truth. Provider-confirmed outcomes therefore require the stronger configured provider verification contract.

## Residual risk

AgentGuard cannot prove that an application did not invoke an uninstrumented executor. It cannot infer hidden dependencies or provider semantics absent from the trusted integration. Hash chains without independently retained checkpoints cannot prove tail completeness. Local SQLite lease fencing does not become distributed consensus across hosts. File-level hardening does not replace kernel isolation, network policy, identity infrastructure, secret-manager policy, external penetration testing, soak testing, or production validation.
