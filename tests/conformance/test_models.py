from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from decisionlock.domain import ActionIntent, PolicyDocument


def test_unknown_intent_field_rejected(intent):
    data = intent.model_dump(mode="json")
    data["unexpected"] = 1
    with pytest.raises(ValidationError):
        ActionIntent.model_validate_json(json.dumps(data))


def test_naive_datetime_rejected(intent):
    data = intent.model_dump(mode="json")
    data["requested_at"] = "2026-01-01T00:00:00"
    with pytest.raises(ValidationError):
        ActionIntent.model_validate_json(json.dumps(data))


def test_duplicate_rule_ids_rejected(policy):
    data = policy.model_dump(mode="json")
    data["rules"].append(data["rules"][0])
    with pytest.raises(ValidationError, match="unique"):
        PolicyDocument.model_validate_json(json.dumps(data))


def test_policy_defaults_deny(policy):
    assert policy.defaults.effect.value == "deny"
