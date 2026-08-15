"""Curated Enterprise ATT&CK technique catalog for Phase 14."""
from .models import MitreTechnique, MitreSubTechnique

DEFAULT_TECHNIQUES = (
    MitreTechnique(id="T1059", name="Command and Scripting Interpreter", tactic_ids=("TA0002",)),
    MitreTechnique(id="T1078", name="Valid Accounts", tactic_ids=("TA0001","TA0003","TA0004","TA0005")),
    MitreTechnique(id="T1110", name="Brute Force", tactic_ids=("TA0006",)),
    MitreTechnique(id="T1021", name="Remote Services", tactic_ids=("TA0008",)),
    MitreTechnique(id="T1046", name="Network Service Scanning", tactic_ids=("TA0007",)),
    MitreTechnique(id="T1087", name="Account Discovery", tactic_ids=("TA0007",)),
    MitreTechnique(id="T1053", name="Scheduled Task/Job", tactic_ids=("TA0003","TA0004")),
    MitreTechnique(id="T1548", name="Abuse Elevation Control Mechanism", tactic_ids=("TA0004","TA0005")),
    MitreTechnique(id="T1562", name="Impair Defenses", tactic_ids=("TA0005",)),
    MitreTechnique(id="T1003", name="OS Credential Dumping", tactic_ids=("TA0006",)),
    MitreTechnique(id="T1555", name="Credentials from Password Stores", tactic_ids=("TA0006",)),
    MitreTechnique(id="T1082", name="System Information Discovery", tactic_ids=("TA0007",)),
    MitreTechnique(id="T1057", name="Process Discovery", tactic_ids=("TA0007",)),
    MitreTechnique(id="T1105", name="Ingress Tool Transfer", tactic_ids=("TA0011",)),
    MitreTechnique(id="T1071", name="Application Layer Protocol", tactic_ids=("TA0011",)),
)

DEFAULT_SUBTECHNIQUES = (
    MitreSubTechnique(id="T1059.001", name="PowerShell", parent_id="T1059", tactic_ids=("TA0002",)),
    MitreSubTechnique(id="T1059.004", name="Unix Shell", parent_id="T1059", tactic_ids=("TA0002",)),
    MitreSubTechnique(id="T1110.001", name="Password Guessing", parent_id="T1110", tactic_ids=("TA0006",)),
    MitreSubTechnique(id="T1110.003", name="Password Spraying", parent_id="T1110", tactic_ids=("TA0006",)),
    MitreSubTechnique(id="T1021.004", name="SSH", parent_id="T1021", tactic_ids=("TA0008",)),
    MitreSubTechnique(id="T1078.004", name="Cloud Accounts", parent_id="T1078", tactic_ids=("TA0001","TA0003","TA0004","TA0005")),
    MitreSubTechnique(id="T1003.001", name="LSASS Memory", parent_id="T1003", tactic_ids=("TA0006",)),
    MitreSubTechnique(id="T1071.001", name="Web Protocols", parent_id="T1071", tactic_ids=("TA0011",)),
)

class TechniqueCatalog:
    def __init__(self, techniques=DEFAULT_TECHNIQUES, subtechniques=DEFAULT_SUBTECHNIQUES):
        tech = tuple(techniques); sub = tuple(subtechniques)
        self._tech = {x.id: x for x in tech}
        self._sub = {x.id: x for x in sub}
        if len(self._tech) != len(tech) or len(self._sub) != len(sub):
            raise ValueError("duplicate MITRE technique IDs")
        for item in self._sub.values():
            if item.parent_id not in self._tech:
                raise ValueError(f"unknown parent technique: {item.parent_id}")
    def get(self, technique_id: str) -> MitreTechnique:
        try: return self._tech[technique_id]
        except KeyError as exc: raise KeyError(f"unknown MITRE technique: {technique_id}") from exc
    def get_subtechnique(self, subtechnique_id: str) -> MitreSubTechnique:
        try: return self._sub[subtechnique_id]
        except KeyError as exc: raise KeyError(f"unknown MITRE sub-technique: {subtechnique_id}") from exc
    def all(self): return tuple(self._tech[k] for k in sorted(self._tech))
    def ids(self): return frozenset(self._tech)
