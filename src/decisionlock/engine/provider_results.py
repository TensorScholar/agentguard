from __future__ import annotations

import json
import math
from hashlib import sha256
from typing import Any


class ProviderResultHashingError(ValueError):
    """Raised when a provider result cannot be deterministically hashed."""


def _validate_and_normalize_json_domain(value: Any) -> Any:
    # None and bool must be handled before int because bool is a subclass of int in Python
    if value is None or isinstance(value, bool):
        return value
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ProviderResultHashingError(
                f"non-finite floating-point value {value!r} is not allowed in provider results"
            )
        return value
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise ProviderResultHashingError("provider result object keys must be strings")
        return {k: _validate_and_normalize_json_domain(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_validate_and_normalize_json_domain(v) for v in value]
    raise ProviderResultHashingError(f"unsupported provider result type: {type(value).__name__}")


def provider_result_bytes(payload: Any) -> bytes:
    """Serialize a provider JSON result deterministically."""
    normalized = _validate_and_normalize_json_domain(payload)
    return json.dumps(
        normalized,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def provider_result_digest(payload: Any) -> str:
    """Generate a deterministic SHA-256 digest for a provider result."""
    return "sha256:" + sha256(provider_result_bytes(payload)).hexdigest()
