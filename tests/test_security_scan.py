from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = REPO_ROOT / "scripts" / "security_scan.py"


def _load_security_scan() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "agentguard_security_scan",
        SCRIPT_PATH,
    )
    assert spec is not None
    assert spec.loader is not None

    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_security_scan_accepts_current_source_tree() -> None:
    module = _load_security_scan()

    assert module.scan_source_tree(REPO_ROOT) == []


@pytest.mark.parametrize(
    ("source", "expected_api"),
    [
        (
            "from cryptography.hazmat.primitives.serialization.pkcs7 import pkcs7_decrypt_der\n",
            "pkcs7_decrypt_der",
        ),
        (
            "from cryptography.hazmat.primitives.serialization import pkcs7\n"
            "pkcs7.pkcs7_decrypt_pem(b'data', None, [])\n",
            "pkcs7_decrypt_pem",
        ),
        (
            "from cryptography.hazmat.primitives.serialization import pkcs7\n"
            "handler = pkcs7.pkcs7_decrypt_smime\n",
            "pkcs7_decrypt_smime",
        ),
        (
            "from cryptography.hazmat.primitives.serialization import pkcs7\n"
            'handler = getattr(pkcs7, "pkcs7_decrypt_der")\n',
            "pkcs7_decrypt_der",
        ),
    ],
)
def test_security_scan_rejects_exception_invalidating_api_usage(
    tmp_path: Path,
    source: str,
    expected_api: str,
) -> None:
    module = _load_security_scan()
    source_file = tmp_path / "src" / "example.py"
    source_file.parent.mkdir()
    source_file.write_text(source, encoding="utf-8")

    findings = module.scan_source_tree(tmp_path)

    assert any(expected_api in finding for finding in findings)
