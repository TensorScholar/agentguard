.PHONY: test coverage schemas check demo package

test:
	PYTHONPATH=src pytest
coverage:
	PYTHONPATH=src coverage run --branch -m pytest && coverage report -m
schemas:
	PYTHONPATH=src python scripts/generate_schemas.py --check
check:
	python -m ruff format --check .
	python -m ruff check .
	python -m mypy src/agentguard
	PYTHONPATH=src python -m pytest
	PYTHONPATH=src python -m coverage run --branch -m pytest
	PYTHONPATH=src python -m coverage report --fail-under=85 -m
	PYTHONPATH=src python scripts/generate_schemas.py --check
	PYTHONPATH=src python scripts/check_architecture.py
	PYTHONPATH=src python scripts/check_secrets.py
	PYTHONPATH=src python scripts/security_scan.py
	python -m compileall -q src tests

demo:
	PYTHONPATH=src python -m agentguard demo --output .agentguard/demo --force
package:
	python -m build
	python -m twine check dist/*
