from __future__ import annotations

import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).parents[1]
BINARY_SUFFIXES = {".bundle", ".gz", ".pem", ".pyc", ".sqlite", ".whl", ".zip"}
PATTERNS = (
    re.compile("AKIA" + r"[0-9A-Z]{16}"),
    re.compile("sk-" + r"[A-Za-z0-9]{20,}"),
    re.compile("-----BEGIN " + r"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
)


def tracked_files() -> list[Path]:
    result = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        check=True,
        capture_output=True,
    )
    return [ROOT / item.decode() for item in result.stdout.split(b"\0") if item]


violations: list[str] = []
for path in tracked_files():
    if not path.is_file() or path.suffix in BINARY_SUFFIXES:
        continue
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        continue
    for pattern in PATTERNS:
        if pattern.search(text):
            violations.append(f"{path.relative_to(ROOT)}: {pattern.pattern}")

if violations:
    raise SystemExit("\n".join(violations))
print("secret scan ok")
