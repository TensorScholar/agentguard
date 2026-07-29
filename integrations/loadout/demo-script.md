# Demo script

```bash
agentguard demo --output .agentguard/loadout-demo
cat .agentguard/loadout-demo/results.json
agentguard evidence-verify .agentguard/loadout-demo/evidence
```

Narration:

- The support agent receives authority for one $85.00 refund in tenant `acme`.
- AgentGuard signs a short-lived decision containing exact digests and a `refund:create` credential ceiling.
- The mock broker returns an opaque handle; no raw credential exists in model-visible data.
- Execution succeeds once.
- Mutating arguments is rejected before execution.
- Reusing the receipt is rejected atomically.
- The final evidence bundle verifies by checksum and the local audit chain verifies independently.
