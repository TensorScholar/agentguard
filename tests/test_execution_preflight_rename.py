"""The preflight rename must fail loudly, not silently.

``authorize_execution`` has been non-consuming since the Q02 supersession. A
caller who still uses the old name must get a hard DeprecationWarning, and the
function must not pretend to provide single-use enforcement.
"""

from __future__ import annotations

import inspect
import warnings

import pytest

from agentguard.engine import execution as execution_module
from agentguard.engine.execution import authorize_execution, preflight_execution


def test_new_name_is_the_canonical_entry_point() -> None:
    assert execution_module.preflight_execution is preflight_execution
    assert "WITHOUT consuming" in (preflight_execution.__doc__ or "")
    assert "does not provide single-use enforcement" in (preflight_execution.__doc__ or "")


def test_deprecated_wrapper_warns_hard() -> None:
    # The wrapper must not be importable-and-silent: constructing any call
    # through the old name has to raise a DeprecationWarning with actionable
    # text, so a stale integration cannot quietly lose replay protection.
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        try:
            authorize_execution(  # type: ignore[arg-type]
                None,
                None,
                None,
                None,  # type: ignore[arg-type]
            )
        except Exception:  # noqa: BLE001 - delegation may fail on the stub args
            pass

    deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert deprecations, "authorize_execution must emit a DeprecationWarning"
    message = str(deprecations[0].message)
    assert "does not consume the decision nonce" in message
    assert "preflight_execution" in message
    assert "reserve_execution" in message


def test_deprecated_wrapper_signature_forwards_keyword_arguments() -> None:
    # The wrapper takes **kwargs so historical keyword call sites keep working;
    # confirm the accepted keywords match the canonical function.
    wrapper_params = inspect.signature(authorize_execution).parameters
    canonical_params = inspect.signature(preflight_execution).parameters
    forwarded = {
        name
        for name, param in wrapper_params.items()
        if param.kind is inspect.Parameter.KEYWORD_ONLY
    }
    for name in forwarded:
        assert name in canonical_params


def test_preflight_does_not_mutate_nonce_state() -> None:
    # Guard the core safety property directly: the preflight body must not
    # consume a nonce even when a nonce repository is supplied. Inspect the
    # body only, excluding the docstring that names the real claiming call.
    body = inspect.getsource(preflight_execution)
    body = body.split('"""', 2)[-1] if body.count('"""') >= 2 else body
    for forbidden in ("consume(", "reserve_execution(", "INSERT INTO consumed_nonces"):
        assert forbidden not in body, forbidden


@pytest.mark.parametrize(
    "module",
    [
        "agentguard.cli.app",
        "agentguard.application.service",
        "agentguard.demo",
    ],
)
def test_product_modules_do_not_call_the_deprecated_name(module: str) -> None:
    import importlib
    from pathlib import Path

    imported = importlib.import_module(module)
    path = Path(inspect.getfile(imported))
    text = path.read_text(encoding="utf-8")
    assert "authorize_execution" not in text, path
