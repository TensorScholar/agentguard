from __future__ import annotations

from importlib.metadata import PackageNotFoundError, version


__version__ = "0.1.0"


def package_version() -> str:
    try:
        return version("agentguard")
    except PackageNotFoundError:
        return __version__
