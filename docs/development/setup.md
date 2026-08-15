# Development Setup

## Requirements

- Python 3.12+
- pip
- Git

## Setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
cp .env.example .env
```

Do not place real secrets in `.env` committed to Git.

## Run

```bash
uvicorn app.main:app --app-dir backend --reload
```

## Quality

```bash
make quality
```
