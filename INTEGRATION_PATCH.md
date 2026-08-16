# Integration Patch — apply manually in the inspected working tree

## `backend/app/main.py`

Add imports:

```python
from app.api.middleware.metrics import MetricsMiddleware
from app.api.routes.metrics import router as metrics_router
```

After the existing `app.add_middleware(RequestIDMiddleware)` call add:

```python
app.add_middleware(MetricsMiddleware)
app.include_router(metrics_router)
```

For dependency-aware readiness, replace the existing `/health/ready` body with:

```python
from app.core.health import readiness_status

@app.get("/health/ready", tags=["health"])
async def ready() -> dict[str, object]:
    health = await readiness_status(
        service=settings.app_name,
        version=version,
        postgres=container.postgres_session_manager,
    )
    return health.as_dict()
```

## `backend/app/api/routes/health.py`

The existing `/api/v1/health` endpoint may remain unchanged for backward
compatibility. The root readiness endpoint is the authoritative dependency
check.

## `pyproject.toml`

No runtime metrics dependency is required. For exact security workflow parity,
add these to `[project.optional-dependencies].dev`:

```toml
"bandit>=1.7,<2.0",
"pip-audit>=2.7,<3.0",
```

## Git hygiene

`project.txt` is an untracked local inspection artifact. It should not be
committed unless intentionally retained.
