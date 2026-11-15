# Threat Model

## Protected properties

DecisionLock is designed to preserve the following properties on traffic that actually crosses a protected adapter:

- the dispatched normalized action must match the signed authorization decision, and credential use must remain within the decision's permitted authority;
- approval, delegated authority, typed releases, and capability leases must not expand their signed bounds;
- credential material must stay inside the approved provider/audience/scope/tenant/lifetime boundary;
- provider secrets must not be persisted in decision grants, external-effect bindings, audit, or execution evidence;
- receipts, approvals, leases, typed releases, and execution permits must not be replayed beyond their allowed use;
- a protected local dispatch admission must not commit after its authorization has expired;
- protected MCP calls must fail closed when current schema/inventory/security context cannot be trusted;
- a non-loopback HTTP listener must not start without the required TLS/authentication/Host controls;
- a potentially committed external effect must remain ambiguous until stronger reconciliation evidence is obtained;
- an expired or superseded reconciliation worker must not commit authoritative resolution state;
- raw credentials and common secret values must not enter DecisionLock-owned retained audit/evidence artifacts;
- audit truncation/replacement must be detectable when signed checkpoints are retained independently;
- evidence authenticity must be verifiable when the corresponding trusted public key/provider verification contract is available.

## Primary threats

The threat set includes argument/action substitution, confused deputy behavior, cross-tenant reuse, receipt/approval/lease replay, credential inflation, stale or poisoned tool inventory, provider endpoint substitution, direct-route MCP bypass, ambiguous external-effect replay, duplicate reconciliation workers, stale-worker commits after lease expiry, host/origin confusion, unauthenticated remote HTTP exposure, metadata-service SSRF, path/URL normalization bypass, symlink races, stdout/backpressure denial of service, audit modification/truncation/replacement, evidence substitution, and broker/credential-source outage bypass.

## Trust boundaries

1. **Agent/model/client process** — untrusted proposal source.
2. **Protocol adapter & trusted normalization** — trusted normalization is an explicit TCB boundary; trusted to parse the supported protocol subset, derive exact action identity, and route protected calls through authorization.
3. **Action-integrity kernel** — trusted deterministic policy, receipt, authority, execution, and reconciliation checks.
4. **Signer/verifier roots** — trusted key boundary; private signing material should remain outside model/tool control.
5. **Credential authority/source** — trusted to resolve only the configured secret/profile and to preserve provider binding.
6. **Provider executor/transport** — trusted transport boundary to send the exact verified effect to the bound provider endpoint.
7. **Provider reconciler** — trusted only to the assurance level it is configured to emit; `PROVIDER_VERIFIED` requires an independently trusted provider verification contract. Local signed evidence does not independently establish external provider business truth.
8. **SQLite state** — trusted local transactional/durability boundary for replay, reservations, execution state, and single-host lease fencing.
9. **Independent checkpoint store** — required to detect complete local-ledger replacement/truncation beyond the retained anchor.
10. **Operating system/network** — outside DecisionLock's control; deployment controls must provide process, filesystem, secret, and egress isolation.

## Explicit assumptions

- Protected traffic actually enters an DecisionLock adapter; hidden alternate routes cannot be ruled out by the library alone.
- The adapter labels identity/provenance/provider binding accurately and does not substitute a different operation after verification.
- Private signing keys and provider secret material are inaccessible to the model and untrusted tools.
- The environment-backed credential source is populated by a deployment mechanism appropriate to the environment; DecisionLock is not the secret vault.
- SQLite coordination participants run on one host against the same local filesystem database with ordinary SQLite locking/durability semantics.
- Provider evidence classified `PROVIDER_VERIFIED` comes only from a reconciler whose provider truth-check contract is independently trusted.
- `mcp-posture` receives every configuration artifact the operator expects it to inspect.
- Signed checkpoints are exported to storage an attacker controlling the local ledger cannot rewrite.
- Public verification keys are distributed through an independently trusted channel.
- A decision receipt is a bearer admission ticket inside its validity window: it binds principal claims, not a holder key, so receipt/grant/approval material must be handled as sensitive until consumed, and preflight success is point-in-time only.

## Important adversarial cases

### Authorization expiry at dispatch admission

For the protected execution path, `RESERVED → DISPATCHING` is the local external-effect admission boundary. SQLite serialization is acquired before the authoritative admission timestamp is sampled; the reserved authority binding, receipt expiry, and applicable field-integrity expiry are checked inside that transaction before the transition commits. Executor invocation occurs only after that committed admission. This does not establish that network transmission, provider receipt, or provider-side business effect occurs before the authorization deadline.

### Ambiguous provider commit

A transport failure after a side-effecting write may mean the provider committed the operation even though DecisionLock did not receive a response. The execution remains `UNKNOWN`; blind retry is forbidden unless the provider contract proves replay safety. Reconciliation is required before retry under the default policy.

### Worker pause beyond lease expiry

A worker may pause after reading provider state, lose its lease, and resume after another worker takes over. The newer worker receives a higher fencing token. The stale worker cannot commit authoritative resolution because the lease owner/token/expiry are revalidated atomically with the write.

### Remote HTTP exposure

Binding the service to a non-loopback interface increases the attack surface. Startup is fail-closed unless TLS certificate/key, Bearer token, and explicit non-wildcard Host allowlist are configured. Browser-reachable Origin enforcement requires an explicit Origin allowlist.

### Evidence forgery versus business truth

A valid DecisionLock signature proves that DecisionLock signed the recorded canonical evidence. It does not prove an unsigned provider's external business truth. Provider-confirmed outcomes therefore require the stronger configured provider verification contract.

### Dispatcher liveness and ambient startup takeover

DecisionLock cannot establish process or executor liveness from shared SQLite state alone. Startup of another process sharing the database is not evidence that the original dispatcher is dead; an in-flight execution may still be communicating with an external provider. Ambient startup takeover is therefore prohibited. Explicit recovery depends on external operational assurance that the active dispatcher is no longer live.

## Residual risk

DecisionLock cannot prove that an application did not invoke an uninstrumented executor, and hidden bypass routes around the enforcement boundary cannot be disproven by DecisionLock alone. It cannot infer hidden dependencies or provider semantics absent from the trusted integration. A crashed executor may leave a record in `DISPATCHING` indefinitely until controlled operator recovery occurs, because shared database state alone cannot determine executor liveness. Process-local reconciliation fairness within a running worker daemon does not provide distributed or cross-restart fairness. Hash chains without independently retained checkpoints cannot prove tail completeness. Local SQLite lease fencing does not become distributed consensus across hosts. File-level hardening does not replace kernel isolation, network policy, identity infrastructure, secret-manager policy, external penetration testing, soak testing, or production validation.
