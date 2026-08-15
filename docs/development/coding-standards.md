# Coding Standards

## Python

- Python 3.12+.
- Type annotations are required for production functions.
- Prefer small functions with one responsibility.
- Avoid global mutable state.
- Avoid unnecessary abstractions.
- Use explicit exceptions and safe error messages.

## Security

- Treat external input as untrusted.
- Never log passwords, tokens, API keys, secrets, or credentials.
- Never hard-code secrets.
- Use environment/configuration mechanisms for deployment values.
- Do not expose stack traces through external responses.

## Architecture

- Preserve dependency direction.
- Domain code must not depend directly on infrastructure implementations.
- CLI commands must not contain business logic.
- Do not create duplicate responsibilities.

## Quality

Ruff and MyPy are authoritative local quality gates for this foundation.
