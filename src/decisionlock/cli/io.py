from __future__ import annotations

import json
from pathlib import Path
from typing import Any, TypeVar

import yaml
from pydantic import BaseModel

from decisionlock.domain import PolicyDocument, ProvenanceLabel
from decisionlock.security.files import read_regular_file, secure_atomic_write

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


def parse_provenance(values: list[str]) -> tuple[ProvenanceLabel, ...]:
    """Translate repeatable --provenance values into labels.

    An empty list yields the UNVERIFIED default rather than an empty tuple, so an
    unconfigured adapter still produces a decidable intent instead of an empty
    provenance set that no policy rule can match.

    Raises ValueError for an unknown label, or for a contradictory mix of
    UNVERIFIED with a trusted label. Callers surface this as a usage error.
    """

    if not values:
        return (ProvenanceLabel.UNVERIFIED,)
    labels: list[ProvenanceLabel] = []
    for raw in values:
        try:
            label = ProvenanceLabel(raw)
        except ValueError as exc:
            known = ", ".join(item.value for item in ProvenanceLabel)
            raise ValueError(f"unknown provenance label {raw!r}; known labels: {known}") from exc
        if label not in labels:
            labels.append(label)
    if ProvenanceLabel.UNVERIFIED in labels and len(labels) > 1:
        raise ValueError(
            "unverified cannot be combined with a trusted provenance label; they are contradictory"
        )
    return tuple(labels)
