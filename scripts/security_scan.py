from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]

FORBIDDEN_CRYPTOGRAPHY_APIS = frozenset(
    {
        "pkcs7_decrypt_der",
        "pkcs7_decrypt_pem",
        "pkcs7_decrypt_smime",
    }
)
PKCS7_MODULE = "cryptography.hazmat.primitives.serialization.pkcs7"


def scan_source_tree(root: Path) -> list[str]:
    source_root = root / "src"
    if not source_root.is_dir():
        return ["src: source tree is missing"]

    findings: list[str] = []

    for path in source_root.rglob("*.py"):
        findings.extend(scan_file(path, root))

    return sorted(set(findings))


def scan_file(path: Path, root: Path) -> list[str]:
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text, path)
    relative_path = path.relative_to(root)
    findings: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module == PKCS7_MODULE:
            for alias in node.names:
                if alias.name == "*" or alias.name in FORBIDDEN_CRYPTOGRAPHY_APIS:
                    findings.append(
                        f"{relative_path}:{node.lineno}: "
                        f"forbidden cryptography PKCS#7 decryption import {alias.name}"
                    )

        referenced_name = _referenced_name(node)
        if referenced_name in FORBIDDEN_CRYPTOGRAPHY_APIS:
            findings.append(
                f"{relative_path}:{node.lineno}: forbidden cryptography API {referenced_name}"
            )

        if not isinstance(node, ast.Call):
            continue

        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            findings.append(f"{relative_path}:{node.lineno}: {node.func.id}")

        if any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            findings.append(f"{relative_path}:{node.lineno}: shell=True")

        if (
            isinstance(node.func, ast.Attribute)
            and node.func.attr == "load"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "yaml"
        ):
            loader = next(
                (keyword.value for keyword in node.keywords if keyword.arg == "Loader"),
                None,
            )
            if not (isinstance(loader, ast.Name) and loader.id.startswith("_Strict")):
                findings.append(f"{relative_path}:{node.lineno}: unsafe yaml.load")

    return findings


def _referenced_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def main() -> None:
    findings = scan_source_tree(ROOT)
    if findings:
        raise SystemExit("\n".join(findings))
    print("static security scan ok")


if __name__ == "__main__":
    main()
