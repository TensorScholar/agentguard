from __future__ import annotations

import sys
from collections.abc import Sequence

from decisionlock.adapters.evidence.bundle import EvidenceVerificationError
from decisionlock.application.service import ExecutionPersistenceError
from decisionlock.changed import changed_config_paths
from decisionlock.compatibility import v1_cli as _v1_cli
from decisionlock.engine.causal import CausalIntegrityError
from decisionlock.engine.credentials import CredentialVerificationError
from decisionlock.engine.execution import ExecutionGuardError
from decisionlock.engine.field_integrity import FieldIntegrityError
from decisionlock.engine.receipts import ReceiptVerificationError
from decisionlock.security.files import UnsafeFilesystemTargetError
from decisionlock.service_deployment import ServiceDeploymentError

from .app import app

# Deterministic denial, integrity, and verification failures. Each carries a stable
# reason code (for example execution.arguments_digest_mismatch or
# evidence.digest_mismatch:grant.json) that operators match on and CI asserts on, so
# the CLI prints the code instead of a Rich traceback.
_DENIAL_ERRORS = (
    ExecutionGuardError,
    ReceiptVerificationError,
    CredentialVerificationError,
    FieldIntegrityError,
    CausalIntegrityError,
    ExecutionPersistenceError,
    EvidenceVerificationError,
    UnsafeFilesystemTargetError,
    ServiceDeploymentError,
)

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
    """Compatibility API for callers of the public v0.1 ``decisionlock.cli.main``."""
    # Preserve the public module-level seam used by integrations and regression tests.
    _v1_cli.changed_config_paths = changed_config_paths
    return _v1_cli.main(argv)


def entrypoint(argv: Sequence[str] | None = None) -> int:
    """Dispatch preserved v0.1 commands and the v0.2 action-integrity CLI."""
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in _V1_ONLY_COMMANDS:
        return _v1_cli.main(args)
    try:
        result = app(args=args, prog_name="decisionlock", standalone_mode=False)
        code = int(result or 0)
        return 0 if code < 0 else code
    except SystemExit as exc:
        code = int(exc.code or 0)
        return 0 if code < 0 else code
    except _DENIAL_ERRORS as exc:
        # These carry stable reason codes that operators are expected to match on.
        # Rendering them as a Rich traceback hides the one line that matters, so
        # print the code plainly on stderr and exit non-zero.
        sys.stderr.write(f"{type(exc).__name__}: {exc}\n")
        return 2


__all__ = ["app", "changed_config_paths", "entrypoint", "main"]
