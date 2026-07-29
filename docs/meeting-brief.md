# Luciana meeting brief

## 30-second framing

AgentGuard is evolving from a local MCP policy proxy into a provider-neutral action-integrity layer. It authorizes an exact action, signs a short-lived decision receipt, constrains the credential a broker may issue, verifies that the final execution still matches the decision, and produces a correlated evidence trail.

**AgentGuard decides and bounds the action. Loadout provisions the minimum credential. Execution is bound to both.**

## Demo sequence

1. A verified support workload requests an $85.00 refund for its own tenant.
2. AgentGuard allows it under a $100.00 blast-radius ceiling and signs a 60-second receipt.
3. The mock broker issues an opaque `refund:create` grant for 30 seconds.
4. The exact action executes once.
5. Changing the amount or order ID is rejected.
6. Reusing the receipt is rejected.
7. The evidence bundle verifies.

## Honest status

The decision, broker contract, credential verifier, execution guard, audit chain and mock integration run locally. The actual Loadout adapter requires their API contract and sandbox.
