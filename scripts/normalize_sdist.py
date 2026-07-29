from __future__ import annotations

import gzip
import io
import sys
import tarfile
from pathlib import Path

EPOCH = 1785283200


def normalize(source: Path, destination: Path) -> None:
    with tarfile.open(source, "r:gz") as src:
        members = sorted(src.getmembers(), key=lambda item: item.name)
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w", format=tarfile.PAX_FORMAT) as dst:
            for member in members:
                member = member.replace(
                    mtime=EPOCH,
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
        gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=EPOCH, compresslevel=9) as gz,
    ):
        gz.write(payload)


if __name__ == "__main__":
    normalize(Path(sys.argv[1]), Path(sys.argv[2]))
