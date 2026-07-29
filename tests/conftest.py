from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from agentguard.adapters.crypto import Ed25519Signer, Ed25519Verifier
from agentguard.adapters.storage.sqlite import SQLiteState
from agentguard.domain import ActionIntent, PolicyDocument

ROOT = Path(__file__).parents[1]


@pytest.fixture
def intent() -> ActionIntent:
    return ActionIntent.model_validate_json(
        (ROOT / "src/agentguard/resources/demo-intent.json").read_text()
    )


@pytest.fixture
def policy() -> PolicyDocument:
    raw = yaml.safe_load((ROOT / "src/agentguard/resources/default_policy_v2.yaml").read_text())
    return PolicyDocument.model_validate_json(json.dumps(raw))


@pytest.fixture
def signer():
    return Ed25519Signer.generate()


@pytest.fixture
def verifier(signer):
    return Ed25519Verifier({signer.key_id: signer.public_key()})


@pytest.fixture
def state(tmp_path):
    return SQLiteState(tmp_path / "state.sqlite")
