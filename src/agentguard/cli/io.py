from __future__ import annotations
import json
from pathlib import Path
from typing import Any, TypeVar
import yaml
from pydantic import BaseModel
from agentguard.domain import PolicyDocument

T = TypeVar("T", bound=BaseModel)

def load_json_model(path: Path, model: type[T]) -> T:
    return model.model_validate_json(path.read_text(encoding="utf-8"))

def load_policy(path: Path) -> PolicyDocument:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    return PolicyDocument.model_validate_json(json.dumps(value))

def write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
