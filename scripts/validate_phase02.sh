#!/usr/bin/env bash
set -euo pipefail

echo "== Phase 02 validation =="

python -m compileall backend
ruff check .
ruff format --check .
mypy .
pytest

echo "Phase 02 validation commands completed successfully."
