from __future__ import annotations

import os
import stat
import tempfile
from pathlib import Path


class UnsafeFilesystemTargetError(ValueError):
    """Raised when a security-sensitive path resolves through a symlink or non-file target."""


def _reject_symlink_components(path: Path) -> None:
    """Reject existing symlink components without requiring the final path to exist."""

    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        current /= part
        try:
            mode = current.lstat().st_mode
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(mode):
            raise UnsafeFilesystemTargetError(f"unsafe symlink component: {current}")


def ensure_private_file(path: Path) -> None:
    """Create or validate a regular, non-symlink file and force owner-only permissions."""

    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(path.parent)
    try:
        mode = path.lstat().st_mode
    except FileNotFoundError:
        flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        os.close(fd)
    else:
        if stat.S_ISLNK(mode) or not stat.S_ISREG(mode):
            raise UnsafeFilesystemTargetError(f"unsafe file target: {path}")
    try:
        path.chmod(0o600)
    except OSError as exc:
        raise UnsafeFilesystemTargetError(f"cannot secure file permissions: {path}") from exc


def secure_atomic_write(path: Path, data: bytes, *, mode: int = 0o600) -> None:
    """Atomically replace a file without following a destination symlink.

    The temporary file is created in the destination directory with its final permissions before
    any content is written. ``os.replace`` replaces a pre-existing symlink rather than following
    it, avoiding the common write-then-chmod and symlink-overwrite races.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    _reject_symlink_components(path.parent)
    try:
        existing_mode = path.lstat().st_mode
    except FileNotFoundError:
        existing_mode = None
    if existing_mode is not None and not (
        stat.S_ISREG(existing_mode) or stat.S_ISLNK(existing_mode)
    ):
        raise UnsafeFilesystemTargetError(f"unsafe file target: {path}")

    fd, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb", closefd=True) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            directory_fd = os.open(path.parent, os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except Exception:
        try:
            os.close(fd)
        except OSError:
            pass
        temporary.unlink(missing_ok=True)
        raise


def read_regular_file(path: Path, *, maximum_bytes: int | None = None) -> bytes:
    """Read a regular file while rejecting symlinks and path substitution where supported.

    ``maximum_bytes`` bounds memory use for attacker-controlled configuration and evidence files.
    """

    if maximum_bytes is not None and maximum_bytes < 0:
        raise ValueError("maximum_bytes cannot be negative")

    _reject_symlink_components(path.parent)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise UnsafeFilesystemTargetError(f"unsafe or unreadable file: {path}") from exc
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode):
            raise UnsafeFilesystemTargetError(f"not a regular file: {path}")
        if maximum_bytes is not None and before.st_size > maximum_bytes:
            raise UnsafeFilesystemTargetError(f"file exceeds configured limit: {path}")
        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(fd, 1024 * 1024)
            if not chunk:
                break
            total += len(chunk)
            if maximum_bytes is not None and total > maximum_bytes:
                raise UnsafeFilesystemTargetError(f"file exceeds configured limit: {path}")
            chunks.append(chunk)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
        ):
            raise UnsafeFilesystemTargetError(f"file changed while reading: {path}")
        return b"".join(chunks)
    finally:
        os.close(fd)
