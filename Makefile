.PHONY: install test lint typecheck check run

install:
	pip install -e ".[dev]"

test:
	pytest -v

lint:
	ruff check .

typecheck:
	mypy src

check: lint typecheck test

run:
	kubesentinel scan
