# Phase 19 Integration Checklist

## 1. Deployment tree

Copy:

```text
deployment/
├── docker/
├── docker-compose/
├── nginx/
├── production/
└── kubernetes/
```

## 2. Backend image

Expected ASGI module:

```text
app.main:app
```

The image uses:

```text
Python 3.13 slim
non-root user
uvicorn
installed project package
```

## 3. Frontend image

The image uses:

```text
Node 22 builder
Nginx runtime
```

The Vite application is built with the existing `npm run build` contract.

## 4. Worker / collector

The repository must provide the actual runtime commands. Set:

```text
WORKER_COMMAND
COLLECTOR_COMMAND
```

Do not replace them with guessed Python module names.

## 5. Production secrets

Never commit real values for:

```text
SIEM_AUTH_SECRET_KEY
SIEM_DATABASE_URL
POSTGRES_PASSWORD
REDIS_PASSWORD
OPENSEARCH_INITIAL_ADMIN_PASSWORD
```

## 6. Verification order

```text
Docker build
→ local smoke test
→ Compose dependency health
→ backend readiness
→ frontend load
→ reverse proxy test
→ Kubernetes dry-run/manifest validation
→ performance benchmark
→ failure testing
```

## 7. Phase boundary

This bundle does not introduce Phase 20 documentation/demo/portfolio work.
