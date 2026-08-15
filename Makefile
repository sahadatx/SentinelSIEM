.PHONY: install test lint format-check typecheck compile quality

install:
	python -m pip install -e ".[dev]"

test:
	pytest

lint:
	ruff check .

format-check:
	ruff format --check .

typecheck:
	mypy .

compile:
	python -m compileall backend

quality: lint format-check typecheck test compile
