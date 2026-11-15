from pathlib import Path

ROOT = Path(__file__).parents[1] / "src/decisionlock"
for path in (ROOT / "domain").glob("*.py"):
    text = path.read_text()
    forbidden = ["sqlite3", "httpx", "starlette", "typer", "decisionlock.adapters"]
    for token in forbidden:
        if token in text:
            raise SystemExit(f"forbidden dependency {token} in {path}")
print("architecture boundaries ok")
