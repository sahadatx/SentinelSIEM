# Security Policy

## Reporting

Do not disclose security-sensitive details in public issues. Use the project's
private security reporting process when one is configured.

## Secure development baseline

- Never commit credentials or private keys.
- Validate untrusted input at trust boundaries.
- Do not leak stack traces through external interfaces.
- Bound resource consumption.
- Keep dependencies maintained and auditable.
- Treat plugins and external integrations as restricted trust boundaries.

See `docs/architecture/threat-model.md` and `docs/development/coding-standards.md`.
