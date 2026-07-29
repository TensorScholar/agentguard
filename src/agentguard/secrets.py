from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class SecretFinding:
    kind: str
    start: int
    end: int


SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("private_key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,255}\b")),
    ("openai_key", re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b")),
    (
        "generic_secret_assignment",
        re.compile(
            r"(?i)\b(api[_-]?key|token|secret|password)\b\s*[:=]\s*['\"]?[^'\"\s]{8,}"
        ),
    ),
)


def find_secrets(text: str) -> list[SecretFinding]:
    findings: list[SecretFinding] = []
    for kind, pattern in SECRET_PATTERNS:
        for match in pattern.finditer(text):
            findings.append(SecretFinding(kind=kind, start=match.start(), end=match.end()))
    return sorted(findings, key=lambda item: item.start)


def redact_text(text: str) -> tuple[str, list[SecretFinding]]:
    findings = find_secrets(text)
    if not findings:
        return text, []

    parts: list[str] = []
    cursor = 0
    for finding in findings:
        if finding.start < cursor:
            continue
        parts.append(text[cursor : finding.start])
        parts.append(f"[REDACTED:{finding.kind}]")
        cursor = finding.end
    parts.append(text[cursor:])
    return "".join(parts), findings


def redact_value(value: object) -> object:
    if isinstance(value, str):
        return redact_text(value)[0]
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(redact_value(item) for item in value)
    if isinstance(value, dict):
        return {str(key): redact_value(item) for key, item in value.items()}
    return value
