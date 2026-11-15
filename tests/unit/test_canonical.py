from __future__ import annotations

from datetime import UTC, datetime
from decimal import Decimal

import pytest

from decisionlock.engine.canonical import CanonicalizationError, canonical_bytes, digest


def test_object_key_order_is_deterministic():
    assert (
        canonical_bytes({"b": 2, "a": 1}) == canonical_bytes({"a": 1, "b": 2}) == b'{"a":1,"b":2}'
    )


def test_set_order_is_deterministic():
    assert canonical_bytes({"x": frozenset({"b", "a"})}) == b'{"x":["a","b"]}'


def test_datetime_is_utc_serialized():
    assert b"2026-01-01T00:00:00Z" in canonical_bytes({"t": datetime(2026, 1, 1, tzinfo=UTC)})


def test_decimal_is_string():
    assert canonical_bytes({"x": Decimal("1.20")}) == b'{"x":"1.20"}'


def test_float_rejected():
    with pytest.raises(CanonicalizationError, match="floating-point"):
        canonical_bytes({"x": 1.5})


def test_non_string_key_rejected():
    with pytest.raises(CanonicalizationError, match="keys"):
        canonical_bytes({1: "x"})


def test_digest_has_prefix():
    assert digest({"x": 1}).startswith("sha256:") and len(digest({"x": 1})) == 71


def test_naive_datetime_rejected_by_canonicalizer():
    from datetime import datetime

    with pytest.raises(CanonicalizationError, match="naive"):
        canonical_bytes({"t": datetime(2026, 1, 1)})  # noqa: DTZ001 - deliberately naive


def test_unsupported_type_rejected():
    with pytest.raises(CanonicalizationError, match="unsupported"):
        canonical_bytes({"x": object()})
