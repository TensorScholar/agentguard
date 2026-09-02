from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version

from ._version import __version__


def package_version() -> str:
    try:
        return version("agentguard")
    except PackageNotFoundError:
        return __version__
