# Trust Boundaries

## Trust Zones

| Zone | Description | Trust Level |
|---|---|---|
| External Sources | Logs and telemetry from external systems | Untrusted |
| Collection | Collectors and receivers | Controlled boundary |
| Processing | Parsing, normalization, enrichment | Controlled |
| Plugins | Third-party/optional extension code | Restricted / isolated |
| Detection | Detection and correlation logic | Controlled |
| Storage | PostgreSQL/OpenSearch/Redis | Protected |
| API | External control/data access | Protected boundary |
| Dashboard | Analyst-facing presentation | Protected |
| Administrators | Privileged human operators | High privilege |
| Threat Intelligence | External feeds/providers | Untrusted external dependency |
| Deployment Infrastructure | Hosts, containers, orchestration | Protected infrastructure |

## Boundary Rules

### External Sources → Collectors

Validate input, enforce limits, and assume malicious or malformed data is possible.

### Receivers → Processing

Normalize transport assumptions and prevent oversized or malformed input from exhausting resources.

### Plugins → Core

Plugins operate behind explicit contracts. Plugin failures must be isolated and observable.

### API → Application Services

Authenticate and authorize requests before protected operations.

### Application → Storage

Use explicit repository/service boundaries and least-privilege credentials.

### External TI → Platform

Validate, normalize, cache, and constrain external intelligence before using it in security decisions.
