from __future__ import annotations
import json
import statistics
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
import yaml
from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.storage.sqlite import SQLiteState
from agentguard.domain import ActionIntent, PolicyDocument
from agentguard.engine.policy import evaluate_policy
from agentguard.engine.receipts import issue_decision_receipt, verify_decision_receipt

ROOT=Path(__file__).parents[1]

def measure(fn, iterations: int) -> dict[str, float]:
    samples=[]
    for _ in range(iterations):
        start=time.perf_counter_ns(); fn(); samples.append((time.perf_counter_ns()-start)/1_000_000)
    ordered=sorted(samples)
    return {
      "iterations":iterations,
      "median_ms":statistics.median(samples),
      "p95_ms":ordered[max(0,int(iterations*0.95)-1)],
      "p99_ms":ordered[max(0,int(iterations*0.99)-1)],
      "max_ms":max(samples),
    }

def main():
    intent=ActionIntent.model_validate_json((ROOT/'src/agentguard/resources/demo-intent.json').read_text())
    policy=PolicyDocument.model_validate_json(json.dumps(yaml.safe_load((ROOT/'src/agentguard/resources/default_policy_v2.yaml').read_text())))
    signer=Ed25519Signer.generate(); verifier=Ed25519Verifier({signer.key_id:signer.public_key()})
    evaluation=evaluate_policy(policy,intent); receipt=issue_decision_receipt(intent,evaluation,signer)
    with tempfile.TemporaryDirectory() as td:
        state=SQLiteState(Path(td)/'state.sqlite')
        counter=iter(range(1000000))
        results={
          "benchmark_type":"synthetic-local",
          "environment":{"python":"local-runtime","storage":"temporary SQLite WAL"},
          "policy_evaluation":measure(lambda:evaluate_policy(policy,intent),5000),
          "receipt_verification":measure(lambda:verify_decision_receipt(receipt,verifier),5000),
          "nonce_consumption":measure(lambda:state.consume(f'n{next(counter)}',receipt.decision_id,datetime.now(timezone.utc)),1000),
          "limitations":["Single-process synthetic benchmark","Not a production capacity claim","No network or real broker latency"],
        }
    out=ROOT/'benchmarks/benchmark-results.json'; out.write_text(json.dumps(results,indent=2,sort_keys=True)+'\n')
    print(json.dumps(results,indent=2))
if __name__=='__main__': main()
