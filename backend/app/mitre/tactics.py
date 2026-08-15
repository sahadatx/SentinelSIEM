"""Enterprise ATT&CK tactic catalog."""
from .models import MitreTactic

DEFAULT_TACTICS = (
    MitreTactic(id="TA0043", name="Reconnaissance"),
    MitreTactic(id="TA0042", name="Resource Development"),
    MitreTactic(id="TA0001", name="Initial Access"),
    MitreTactic(id="TA0002", name="Execution"),
    MitreTactic(id="TA0003", name="Persistence"),
    MitreTactic(id="TA0004", name="Privilege Escalation"),
    MitreTactic(id="TA0005", name="Defense Evasion"),
    MitreTactic(id="TA0006", name="Credential Access"),
    MitreTactic(id="TA0007", name="Discovery"),
    MitreTactic(id="TA0008", name="Lateral Movement"),
    MitreTactic(id="TA0009", name="Collection"),
    MitreTactic(id="TA0011", name="Command and Control"),
    MitreTactic(id="TA0010", name="Exfiltration"),
    MitreTactic(id="TA0040", name="Impact"),
)

class TacticCatalog:
    def __init__(self, tactics=DEFAULT_TACTICS):
        items = tuple(tactics)
        self._items = {x.id: x for x in items}
        if len(self._items) != len(items):
            raise ValueError("duplicate MITRE tactic IDs")
    def get(self, tactic_id: str) -> MitreTactic:
        try: return self._items[tactic_id]
        except KeyError as exc: raise KeyError(f"unknown MITRE tactic: {tactic_id}") from exc
    def all(self) -> tuple[MitreTactic, ...]:
        return tuple(self._items[k] for k in sorted(self._items))
    def ids(self) -> frozenset[str]:
        return frozenset(self._items)
