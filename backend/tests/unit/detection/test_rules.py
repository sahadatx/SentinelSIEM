from __future__ import annotations

from pathlib import Path

import pytest

from app.detection.rules.loader import DetectionRuleLoader
from app.detection.rules.validator import DetectionRuleValidator


def test_detection_rule_loader_loads_yaml() -> None:
    path = Path("rules/detection/suspicious_login.yaml")
    rule = DetectionRuleLoader(DetectionRuleValidator()).load_file(path)

    assert rule.id == "suspicious-login"
    assert rule.enabled is True


def test_detection_rule_loader_rejects_non_yaml(tmp_path: Path) -> None:
    path = tmp_path / "rule.txt"
    path.write_text("invalid", encoding="utf-8")

    with pytest.raises(ValueError, match="unsupported rule format"):
        DetectionRuleLoader().load_file(path)
