.PHONY: install dev test lint format-check typecheck compile quality

install:
	python -m pip install -e ".[dev]"

dev:
	python tools/dev_server.py

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