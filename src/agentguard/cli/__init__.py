from __future__ import annotations

import sys
from collections.abc import Sequence

from agentguard.changed import changed_config_paths
from agentguard.compatibility import v1_cli as _v1_cli

from .app import app, refuse_mcp_proxy

_V1_ONLY_COMMANDS = frozenset(
    {
        "doctor",
        "scan",
        "gate",
        "check-call",
        "proxy",
        "approve-call",
        "approvals",
        "legacy-mcp-proxy",
        "report",
        "verify-audit",
    }
)


def _run_v1(args: list[str] | None) -> int:
    # Preserve the public module-level seam used by integrations and regression tests.
    _v1_cli.changed_config_paths = changed_config_paths
    return _v1_cli.main(args)


def main(argv: list[str] | None = None) -> int:
    """Compatibility API for callers of the public ``agentguard.cli.main``."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] == "mcp-proxy":
        return entrypoint(args)
    return _run_v1(args)


def entrypoint(argv: Sequence[str] | None = None) -> int:
    """Dispatch explicit v0.1 compatibility commands and the v0.2 CLI."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in _V1_ONLY_COMMANDS:
        return _run_v1(args)
    if args and args[0] == "mcp-proxy" and args[1:] != ["--help"]:
        return refuse_mcp_proxy()
    try:
        app(args=args, prog_name="agentguard", standalone_mode=False)
    except SystemExit as exc:
        return int(exc.code or 0)
    return 0


__all__ = ["app", "changed_config_paths", "entrypoint", "main"]
