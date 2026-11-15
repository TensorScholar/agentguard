"""Security hardening helpers shared by storage, key, and evidence adapters."""

from .files import ensure_private_file, read_regular_file, secure_atomic_write

__all__ = ["ensure_private_file", "read_regular_file", "secure_atomic_write"]
