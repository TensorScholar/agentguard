.PHONY: test coverage schemas check demo package

test:
	PYTHONPATH=src pytest
coverage:
	PYTHONPATH=src coverage run --branch -m pytest && coverage report -m
schemas:
	PYTHONPATH=src python scripts/generate_schemas.py
check: schemas
	PYTHONPATH=src python scripts/check_architecture.py
	PYTHONPATH=src pytest
	PYTHONPATH=src python -m compileall -q src tests

demo:
	PYTHONPATH=src python -m agentguard demo --output .agentguard/demo --force
package:
	python setup.py sdist
	python -m pip wheel . --no-deps -w dist
