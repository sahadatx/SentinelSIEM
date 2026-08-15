# Contributing

## Engineering rules

1. Preserve the locked project architecture.
2. Keep business logic out of CLI commands.
3. Keep domain code independent of infrastructure.
4. Prefer small, typed, testable functions.
5. Add tests for behavior changes.
6. Never commit real secrets.
7. Run formatting, linting, type checking, and tests before submitting changes.
8. Update documentation when behavior or architecture changes.
9. Do not introduce future-phase functionality without a justified boundary need.

## Local quality gate

```bash
make quality
```
