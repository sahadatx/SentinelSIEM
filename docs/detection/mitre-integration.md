# Phase 14 — MITRE ATT&CK Integration

SentinelSIEM maps detection rules to ATT&CK tactics, techniques and sub-techniques.

## Boundary

The module is storage-agnostic and exposes a stable service boundary. API,
authentication, dashboard and dynamic external feed ingestion remain in later
roadmap phases.

## Example

```python
from app.mitre import MitreService

service = MitreService()
service.map_detection(
    detection_id="brute-force-plugin",
    technique_id="T1110",
    subtechnique_id="T1110.001",
    tactic_ids=("TA0006",),
    confidence=0.95,
)
print(service.coverage())
print(service.navigator_layer())
```

## Security

ATT&CK identifiers are validated, parent/sub-technique relationships are
checked, unknown references are rejected, and conflicting mappings cannot be
silently overwritten.
