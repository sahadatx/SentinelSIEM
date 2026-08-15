from __future__ import annotations

from pathlib import Path

import yaml

from app.correlation.schema import CorrelationRule


def load_rule(path: Path) -> CorrelationRule:
    if path.suffix.lower() not in {".yaml", ".yml"}:
        raise ValueError(f"unsupported correlation rule file: {path.name}")
    with path.open("r", encoding="utf-8") as handle:
        payload = yaml.safe_load(handle)
    if not isinstance(payload, dict):
        raise ValueError(f"correlation rule must be a mapping: {path}")
    return CorrelationRule.model_validate(payload)


def load_rules(directory: Path) -> tuple[CorrelationRule, ...]:
    rules: list[CorrelationRule] = []
    for path in sorted(directory.glob("*.y*ml")):
        rules.append(load_rule(path))
    return tuple(rules)
