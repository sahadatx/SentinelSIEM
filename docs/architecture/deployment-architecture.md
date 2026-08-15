# Deployment Architecture

## 1. Deployment Model

The initial deployment model is:

- Modular monolith for core application capabilities.
- Independently scalable workers for data-plane processing.
- Event-driven processing.
- Plugin-based extension.
- Docker and Docker Compose support.
- Kubernetes-ready architecture.
- Nginx as a reverse proxy where appropriate.

## 2. Logical Deployment

```text
                    Client / Analyst
                           │
                         Nginx
                           │
                 ┌─────────▼─────────┐
                 │       API         │
                 └─────────┬─────────┘
                           │
                 ┌─────────▼─────────┐
                 │ Application Core  │
                 └───────┬───┬───────┘
                         │   │
             ┌───────────┘   └─────────────┐
             ▼                             ▼
        PostgreSQL                       Redis
             │                             │
             └──────────────┬──────────────┘
                            ▼
                         Workers
                            │
                            ▼
                        OpenSearch
```

Collectors and workers may be scaled independently as throughput requirements grow.

## 3. Security Deployment Principles

- Do not bake secrets into images.
- Prefer non-root containers.
- Use minimal images.
- Apply health checks.
- Apply resource limits.
- Drop unnecessary Linux capabilities.
- Prefer read-only filesystems where practical.
- Isolate network paths by responsibility.
- Use TLS for production-sensitive communication.

## 4. Kubernetes Readiness

The architecture should permit separate deployments for API, workers, collectors, and supporting infrastructure without requiring the core domain model to become microservice-dependent.

## 5. Deployment Boundary

Deployment configuration is separate from application business logic. Environment-specific secrets and credentials are provided through environment/deployment secret mechanisms rather than committed configuration.
