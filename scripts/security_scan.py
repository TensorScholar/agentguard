from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).parents[1]
findings: list[str] = []

for path in (ROOT / "src").rglob("*.py"):
    text = path.read_text(encoding="utf-8")
    tree = ast.parse(text, path)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        if isinstance(node.func, ast.Name) and node.func.id in {"eval", "exec"}:
            findings.append(f"{path.relative_to(ROOT)}:{node.lineno}: {node.func.id}")
        if any(
            keyword.arg == "shell"
            and isinstance(keyword.value, ast.Constant)
            and keyword.value.value is True
            for keyword in node.keywords
        ):
            findings.append(f"{path.relative_to(ROOT)}:{node.lineno}: shell=True")
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
            if not (
                isinstance(loader, ast.Name)
                and loader.id.startswith("_Strict")
            ):
                findings.append(f"{path.relative_to(ROOT)}:{node.lineno}: unsafe yaml.load")

if findings:
    raise SystemExit("\n".join(findings))
print("static security scan ok")
