from __future__ import annotations
import json
from datetime import datetime
from decimal import Decimal
from enum import Enum
from hashlib import sha256
from pathlib import Path
from typing import Any
from pydantic import BaseModel

class CanonicalizationError(ValueError):
    pass

def _normalize(value: Any) -> Any:
    if isinstance(value, BaseModel):
        return _normalize(value.model_dump(mode="python"))
    if isinstance(value, Enum):
        return value.value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            raise CanonicalizationError("naive datetime is not allowed")
        return value.isoformat().replace("+00:00", "Z")
    if isinstance(value, Decimal):
        return format(value, "f")
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        if not all(isinstance(k, str) for k in value):
            raise CanonicalizationError("object keys must be strings")
        return {k: _normalize(v) for k,v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_normalize(v) for v in value]
    if isinstance(value, (set, frozenset)):
        normalized=[_normalize(v) for v in value]
        return sorted(normalized, key=lambda x: json.dumps(x, sort_keys=True, separators=(",",":"), ensure_ascii=False))
    if isinstance(value, float):
        raise CanonicalizationError("floating-point values are not supported in signed payloads")
    if value is None or isinstance(value, (str,int,bool)):
        return value
    raise CanonicalizationError(f"unsupported canonical type: {type(value).__name__}")

def canonical_bytes(value: Any) -> bytes:
    normalized=_normalize(value)
    return json.dumps(normalized, sort_keys=True, separators=(",",":"), ensure_ascii=False, allow_nan=False).encode("utf-8")

def digest(value: Any) -> str:
    return "sha256:" + sha256(canonical_bytes(value)).hexdigest()
