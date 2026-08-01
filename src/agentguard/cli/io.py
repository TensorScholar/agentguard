from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel

from agentguard.domain import PolicyDocument
from agentguard.security.files import read_regular_file, secure_atomic_write

T = TypeVar("T", bound=BaseModel)


def load_json_model(path: Path, model: type[T]) -> T:
    return model.model_validate_json(read_regular_file(path, maximum_bytes=16 * 1024 * 1024))


def load_policy(path: Path) -> PolicyDocument:
    value = yaml.safe_load(read_regular_file(path, maximum_bytes=16 * 1024 * 1024))
    return PolicyDocument.model_validate_json(json.dumps(value))


def write_json(path: Path, value: Any) -> None:
    payload = value.model_dump(mode="json") if hasattr(value, "model_dump") else value
    secure_atomic_write(
        path,
        (json.dumps(payload, indent=2, sort_keys=True) + "\n").encode("utf-8"),
        mode=0o600,
    )
