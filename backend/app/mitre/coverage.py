"""MITRE ATT&CK coverage and Navigator representation."""
from .models import CoverageResult, NavigatorLayer
from .mappings import MappingRegistry
from .techniques import TechniqueCatalog

class CoverageAnalyzer:
    def __init__(self, catalog: TechniqueCatalog, mappings: MappingRegistry):
        self.catalog = catalog
        self.mappings = mappings
    def calculate(self) -> CoverageResult:
        all_ids = self.catalog.ids()
        mapped = self.mappings.mapped_technique_ids() & all_ids
        percent = round((len(mapped) / len(all_ids)) * 100.0, 2) if all_ids else 0.0
        return CoverageResult(
            total_techniques=len(all_ids),
            mapped_techniques=len(mapped),
            coverage_percent=percent,
            mapped_technique_ids=tuple(sorted(mapped)),
            unmapped_technique_ids=tuple(sorted(all_ids - mapped)),
        )
    def navigator_layer(self, name="SentinelSIEM MITRE Coverage", description=""):
        return NavigatorLayer(name=name, description=description,
                              techniques=self.mappings.navigator_techniques())
