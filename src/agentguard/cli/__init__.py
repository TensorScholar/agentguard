from __future__ import annotations

import sys
from collections.abc import Sequence

from agentguard.changed import changed_config_paths
from agentguard.compatibility import v1_cli as _v1_cli

from .app import app

_V1_ONLY_COMMANDS = frozenset(
    {
        "doctor",
        "scan",
        "gate",
        "check-call",
        "proxy",
        "approve-call",
        "approvals",
        "mcp-proxy",
        "report",
        "verify-audit",
    }
)


def main(argv: list[str] | None = None) -> int:
    """Compatibility API for callers of the public v0.1 ``agentguard.cli.main``."""
    # Preserve the public module-level seam used by integrations and regression tests.
    _v1_cli.changed_config_paths = changed_config_paths
    return _v1_cli.main(argv)


def entrypoint(argv: Sequence[str] | None = None) -> int:
    """Dispatch preserved v0.1 commands and the v0.2 action-integrity CLI."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in _V1_ONLY_COMMANDS:
        return _v1_cli.main(args)
    try:
        result = app(args=args, prog_name="agentguard", standalone_mode=False)
        code = int(result or 0)
        return 0 if code < 0 else code
    except SystemExit as exc:
        code = int(exc.code or 0)
        return 0 if code < 0 else code


__all__ = ["app", "changed_config_paths", "entrypoint", "main"]
