from __future__ import annotations

from decisionlock.secrets import find_secrets, redact_text


def test_redacts_common_token_shapes() -> None:
    synthetic_token = "sk-" + "abcdefghijklmnopqrstuvwxyz"
    redacted, findings = redact_text("OPENAI_API_KEY=" + synthetic_token)

    assert findings
    assert synthetic_token not in redacted
    assert "[REDACTED:" in redacted


def test_find_private_key_marker() -> None:
    findings = find_secrets("-----BEGIN " + "PRIVATE KEY-----")

    assert findings[0].kind == "private_key"
