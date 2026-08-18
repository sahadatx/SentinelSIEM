# SentinelSIEM Production Deployment

## Security baseline

- Run application containers as non-root users.
- Keep PostgreSQL, Redis, and OpenSearch on internal networks only.
- Do not commit production secrets.
- Keep `SIEM_DEBUG=false` in production.
- Supply an authentication secret with at least 32 characters.
- Terminate TLS at the reverse proxy or ingress layer.
- Apply CPU/memory limits before production rollout.
- Validate liveness/readiness before sending traffic.

## Runtime order

1. Start PostgreSQL, Redis, and OpenSearch.
2. Wait for dependency health.
3. Start backend.
4. Verify `/health/live` and `/health/ready`.
5. Start worker/collector processes with the real project entrypoints.
6. Start frontend.
7. Put Nginx/Ingress in front of the application.

## Rollback

Keep versioned image tags and database migration history. Never use a mutable `latest` production tag as the rollback reference.
