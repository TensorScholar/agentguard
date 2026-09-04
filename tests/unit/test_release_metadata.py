from __future__ import annotations

from importlib.metadata import PackageNotFoundError

import agentguard._meta as meta
from agentguard import __version__


def test_package_version_falls_back_to_runtime_version(monkeypatch) -> None:
    def missing(_: str) -> str:
        raise PackageNotFoundError("agentguard")

    monkeypatch.setattr(meta, "version", missing)
    assert meta.package_version() == __version__
