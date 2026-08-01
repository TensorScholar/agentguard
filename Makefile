.PHONY: test coverage schemas lint typecheck security check demo package

test:
	PYTHONPATH=src python -m pytest

coverage:
	PYTHONPATH=src python -m coverage erase
	PYTHONPATH=src python -m coverage run -m pytest
	PYTHONPATH=src python -m coverage report

schemas:
	PYTHONPATH=src python scripts/generate_schemas.py --check

lint:
	python -m ruff format --check src tests scripts
	python -m ruff check src tests scripts

typecheck:
	python -m mypy src/agentguard

security:
	PYTHONPATH=src python scripts/check_architecture.py
	PYTHONPATH=src python scripts/check_secrets.py
	PYTHONPATH=src python scripts/security_scan.py

check: lint typecheck coverage schemas security
	python -m compileall -q src tests scripts

demo:
	PYTHONPATH=src python -m agentguard demo --output .agentguard/demo --force

package:
	python -m build
	python -m twine check dist/*
