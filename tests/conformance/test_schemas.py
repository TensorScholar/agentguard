from __future__ import annotations

import json
from pathlib import Path

import jsonschema

ROOT = Path(__file__).parents[2]


def test_generated_schemas_are_valid_json_schema():
    files = sorted((ROOT / "schemas").glob("*.schema.json"))
    expected = {
        "action-intent-v1.schema.json",
        "approval-receipt-v1.schema.json",
        "audit-checkpoint-v1.schema.json",
        "audit-event-v1.schema.json",
        "credential-grant-v1.schema.json",
        "credential-request-v1.schema.json",
        "decision-receipt-v1.schema.json",
        "evidence-attestation-v1.schema.json",
        "execution-outcome-v1.schema.json",
        "execution-request-v1.schema.json",
        "policy-v2.schema.json",
    }
    assert {path.name for path in files} == expected
    for path in files:
        schema = json.loads(path.read_text())
        jsonschema.Draft202012Validator.check_schema(schema)


def test_demo_intent_validates_against_schema():
    schema = json.loads((ROOT / "schemas/action-intent-v1.schema.json").read_text())
    instance = json.loads((ROOT / "examples/scoped-refund/request.json").read_text())
    jsonschema.validate(instance=instance, schema=schema)
