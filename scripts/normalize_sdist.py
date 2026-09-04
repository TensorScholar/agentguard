from __future__ import annotations

import gzip
import io
import os
import sys
import tarfile
from pathlib import Path


def _source_date_epoch() -> int:
    raw = os.environ.get("SOURCE_DATE_EPOCH")
    if raw is None:
        raise ValueError("SOURCE_DATE_EPOCH is required for reproducible sdist normalization")
    try:
        epoch = int(raw)
    except ValueError as exc:
        raise ValueError("SOURCE_DATE_EPOCH must be an integer") from exc
    if epoch < 0:
        raise ValueError("SOURCE_DATE_EPOCH must be non-negative")
    return epoch


def normalize(source: Path, destination: Path, *, epoch: int | None = None) -> None:
    normalized_epoch = _source_date_epoch() if epoch is None else epoch
    if normalized_epoch < 0:
        raise ValueError("epoch must be non-negative")
    with tarfile.open(source, "r:gz") as src:
        members = sorted(src.getmembers(), key=lambda item: item.name)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as dst:
            for member in members:
                member = member.replace(
                    mtime=normalized_epoch,
                    uid=0,
                    gid=0,
                    uname="",
                    gname="",
                )
                member.pax_headers = {}
                fileobj = src.extractfile(member) if member.isfile() else None
                dst.addfile(member, fileobj)
        payload = buffer.getvalue()
    destination.parent.mkdir(parents=True, exist_ok=True)
    with (
        destination.open("wb") as raw,
        gzip.GzipFile(
            filename="",
            mode="wb",
            fileobj=raw,
            mtime=normalized_epoch,
            compresslevel=9,
        ) as gz,
    ):
        gz.write(payload)


if __name__ == "__main__":
    normalize(Path(sys.argv[1]), Path(sys.argv[2]))
