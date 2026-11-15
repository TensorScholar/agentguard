from __future__ import annotations

from importlib.metadata import PackageNotFoundError

import decisionlock._meta as meta
from decisionlock import __version__


def test_package_version_falls_back_to_runtime_version(monkeypatch) -> None:
    def missing(_: str) -> str:
        raise PackageNotFoundError("decisionlock")

    monkeypatch.setattr(meta, "version", missing)
    assert meta.package_version() == __version__
