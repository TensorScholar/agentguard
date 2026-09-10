from __future__ import annotations

import pytest

from agentguard.engine.provider_results import (
    ProviderResultHashingError,
    provider_result_bytes,
    provider_result_digest,
)


def test_provider_result_integers():
    assert provider_result_bytes({"v": 0}) == b'{"v":0}'
    assert provider_result_bytes({"v": 42}) == b'{"v":42}'
    digest_0 = provider_result_digest({"v": 0})
    assert digest_0.startswith("sha256:") and len(digest_0) == 71


def test_provider_result_finite_floats():
    assert provider_result_bytes({"v": 0.5}) == b'{"v":0.5}'
    assert provider_result_bytes({"v": 12.34}) == b'{"v":12.34}'
    assert provider_result_bytes({"v": 1e-6}) == b'{"v":1e-06}'
    digest_half = provider_result_digest({"v": 0.5})
    assert digest_half.startswith("sha256:") and len(digest_half) == 71


def test_provider_result_nested_finite_floats():
    payload = {
        "metrics": {
            "score": 0.95,
            "rates": [0.1, 0.25, 0.003],
        },
        "status": "ok",
    }
    encoded = provider_result_bytes(payload)
    assert b'"score":0.95' in encoded
    assert b'"rates":[0.1,0.25,0.003]' in encoded
    digest_nested = provider_result_digest(payload)
    assert digest_nested.startswith("sha256:") and len(digest_nested) == 71


def test_provider_result_unicode_strings():
    payload = {"greeting": "سلام", "symbol": "🚀"}
    encoded = provider_result_bytes(payload)
    assert encoded == '{"greeting":"سلام","symbol":"🚀"}'.encode("utf-8")


def test_provider_result_deterministic_key_ordering():
    payload1 = {"b": 2, "a": 1, "c": 3.14}
    payload2 = {"c": 3.14, "b": 2, "a": 1}
    assert provider_result_bytes(payload1) == provider_result_bytes(payload2)
    assert provider_result_digest(payload1) == provider_result_digest(payload2)
    assert provider_result_bytes(payload1) == b'{"a":1,"b":2,"c":3.14}'


def test_provider_result_characterize_zeros():
    # 0.0 and -0.0 both serialize as valid finite floats in standard JSON
    bytes_pos = provider_result_bytes({"v": 0.0})
    bytes_neg = provider_result_bytes({"v": -0.0})
    assert bytes_pos == b'{"v":0.0}'
    assert bytes_neg == b'{"v":-0.0}'
    digest_pos = provider_result_digest({"v": 0.0})
    digest_neg = provider_result_digest({"v": -0.0})
    assert digest_pos.startswith("sha256:")
    assert digest_neg.startswith("sha256:")
    # The raw token distinction is preserved in IEEE-754 JSON serialization
    assert digest_pos != digest_neg


def test_provider_result_reject_nan():
    with pytest.raises(ProviderResultHashingError, match="non-finite"):
        provider_result_digest({"v": float("nan")})


def test_provider_result_reject_infinity():
    with pytest.raises(ProviderResultHashingError, match="non-finite"):
        provider_result_digest({"v": float("inf")})
    with pytest.raises(ProviderResultHashingError, match="non-finite"):
        provider_result_digest({"v": float("-inf")})


def test_provider_result_reject_non_string_keys():
    with pytest.raises(ProviderResultHashingError, match="keys must be strings"):
        provider_result_digest({1: "value"})


def test_provider_result_reject_tuple():
    with pytest.raises(ProviderResultHashingError, match="unsupported provider result type: tuple"):
        provider_result_digest({"items": (1, 2)})


def test_provider_result_reject_arbitrary_object():
    class CustomObject:
        pass

    with pytest.raises(ProviderResultHashingError, match="unsupported provider result type"):
        provider_result_digest({"obj": CustomObject()})
