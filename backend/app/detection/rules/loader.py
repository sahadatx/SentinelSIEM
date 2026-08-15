from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.detection.schema import DetectionRule


class DetectionRuleLoader:
    """Load detection rules from external YAML files."""

    def __init__(self, validator: Any | None = None) -> None:
        self.validator = validator

    def load_file(self, path: Path) -> DetectionRule:
        if path.suffix.lower() not in {".yaml", ".yml"}:
            raise ValueError(f"unsupported rule format: {path.suffix}")

        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)

        if not isinstance(data, dict):
            raise ValueError(f"rule file must contain an object: {path}")

        rule = DetectionRule.model_validate(data)
        if self.validator is not None:
            self.validator.validate(rule)
        return rule

    def load_directory(self, directory: Path) -> tuple[DetectionRule, ...]:
        if not directory.is_dir():
            raise ValueError(f"rule directory does not exist: {directory}")

        rules: list[DetectionRule] = []
        for path in sorted(directory.glob("*.y*ml")):
            rules.append(self.load_file(path))
        return tuple(rules)
