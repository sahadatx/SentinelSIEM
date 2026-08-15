from __future__ import annotations

import subprocess
import sys
from pathlib import Path


# =============================================================================
# SENTINELSIEM
# MASTER VALIDATION — PHASE 01 → PHASE 13
#
# This test uses the current SentinelSIEM project structure.
#
# Important:
# - Phase 01-06 validate the currently implemented architecture/module surface.
# - Phase 07-13 execute the existing real integration tests.
# - No Phase 14+ implementation or validation is included.
# =============================================================================


ATTACKER_IP = "203.0.113.50"
TARGET_HOST = "web-prod-01"
TARGET_USER = "admin"


# =============================================================================
# PROJECT ROOT
# =============================================================================


def find_project_root() -> Path:
    current = Path(__file__).resolve()

    for directory in (current, *current.parents):
        if (
            (directory / "backend").is_dir()
            and (directory / "pyproject.toml").is_file()
        ):
            return directory

    raise RuntimeError(
        "SentinelSIEM project root could not be detected."
    )


PROJECT_ROOT = find_project_root()
BACKEND = PROJECT_ROOT / "backend"
APP = BACKEND / "app"
INTEGRATION = BACKEND / "tests" / "integration"


if str(BACKEND) not in sys.path:
    sys.path.insert(0, str(BACKEND))


# =============================================================================
# OUTPUT HELPERS
# =============================================================================


def banner(title: str) -> None:
    print()
    print("=" * 78)
    print(title)
    print("=" * 78)


def require_files(
    phase: int,
    files: list[str],
) -> None:
    missing = [
        relative
        for relative in files
        if not (PROJECT_ROOT / relative).is_file()
    ]

    if missing:
        print()
        print(f"[FAIL] Phase {phase:02d} missing files:")

        for item in missing:
            print(f"       - {item}")

        raise AssertionError(
            f"Phase {phase:02d} validation failed. "
            f"Missing {len(missing)} required file(s)."
        )


def require_directories(
    phase: int,
    directories: list[str],
) -> None:
    missing = [
        relative
        for relative in directories
        if not (PROJECT_ROOT / relative).is_dir()
    ]

    if missing:
        print()
        print(f"[FAIL] Phase {phase:02d} missing directories:")

        for item in missing:
            print(f"       - {item}")

        raise AssertionError(
            f"Phase {phase:02d} validation failed. "
            f"Missing {len(missing)} required directory(s)."
        )


# =============================================================================
# PHASE 01
# =============================================================================


def validate_phase01() -> None:
    banner(
        "PHASE 01 — REQUIREMENTS & SECURITY ARCHITECTURE"
    )

    require_directories(
        1,
        [
            "docs",
            "config",
        ],
    )

    documentation_files = [
        path
        for path in (PROJECT_ROOT / "docs").rglob("*")
        if path.is_file()
    ]

    configuration_files = [
        path
        for path in (PROJECT_ROOT / "config").rglob("*")
        if path.is_file()
    ]

    assert documentation_files, (
        "Phase 01: no documentation files found."
    )

    assert configuration_files, (
        "Phase 01: no configuration files found."
    )

    print(
        f"Documentation files : "
        f"{len(documentation_files)}"
    )

    print(
        f"Configuration files : "
        f"{len(configuration_files)}"
    )

    print("[PASS] Phase 01")


# =============================================================================
# PHASE 02
# =============================================================================


def validate_phase02() -> None:
    banner(
        "PHASE 02 — PROJECT FOUNDATION"
    )

    require_files(
        2,
        [
            "backend/app/main.py",
            "backend/app/bootstrap.py",
            "backend/app/core/config.py",
            "backend/app/core/constants.py",
            "backend/app/core/dependencies.py",
            "backend/app/core/exceptions.py",
            "backend/app/core/feature_flags.py",
            "backend/app/core/health.py",
            "backend/app/core/lifecycle.py",
            "backend/app/core/logging.py",
            "backend/app/core/security.py",
            "backend/app/core/version.py",
        ],
    )

    from app.main import build_application

    application = build_application()

    assert application is not None
    assert getattr(application, "title", None)

    print(
        f"Application : {application.title}"
    )

    from fastapi.testclient import TestClient

    with TestClient(application) as client:
        live = client.get("/health/live")
        ready = client.get("/health/ready")

    assert live.status_code == 200, (
        f"/health/live returned {live.status_code}"
    )

    assert ready.status_code == 200, (
        f"/health/ready returned {ready.status_code}"
    )

    print(
        f"Live  : {live.status_code} "
        f"{live.json()}"
    )

    print(
        f"Ready : {ready.status_code} "
        f"{ready.json()}"
    )

    print("[PASS] Phase 02")


# =============================================================================
# PHASE 03
# =============================================================================


def validate_phase03() -> None:
    banner(
        "PHASE 03 — EVENT SCHEMA & DATA MODEL"
    )

    require_files(
        3,
        [
            "backend/app/domain/events/__init__.py",
            "backend/app/domain/events/enums.py",
            "backend/app/domain/events/factory.py",
            "backend/app/domain/events/identifiers.py",
            "backend/app/domain/events/models.py",
            "backend/app/domain/events/schema.py",
            "backend/app/domain/events/validation.py",
        ],
    )

    from app.domain.events.factory import create_raw_event
    from app.domain.events.models import RawEvent

    from app.domain.events.enums import EventSourceType

    event = create_raw_event(
        source="sshd",
        source_type=EventSourceType.SYSLOG,
        raw_event=(
            "Aug 15 10:15:32 sentinel-host sshd[4242]: "
            "Failed password for invalid user "
            f"{TARGET_USER} from {ATTACKER_IP} "
            "port 54321 ssh2"
        ),
    )

    assert isinstance(event, RawEvent)
    assert event.event_id
    assert event.source == "sshd"
    assert event.raw_event

    print(
        f"Raw event ID : {event.event_id}"
    )

    print(
        f"Source       : {event.source}"
    )

    print("[PASS] Phase 03")


# =============================================================================
# PHASE 04
# =============================================================================


def validate_phase04() -> None:
    banner(
        "PHASE 04 — LOG COLLECTION & INGESTION"
    )

    require_files(
        4,
        [
            "backend/app/ingestion/__init__.py",
            "backend/app/ingestion/backpressure.py",
            "backend/app/ingestion/dead_letter.py",
            "backend/app/ingestion/manager.py",
            "backend/app/ingestion/pipeline.py",
            "backend/app/ingestion/retry.py",
            "backend/app/ingestion/router.py",
            "backend/app/ingestion/collectors/base.py",
            "backend/app/ingestion/collectors/registry.py",
            "backend/app/ingestion/queues/base.py",
            "backend/app/ingestion/queues/dead_letter.py",
            "backend/app/ingestion/queues/redis.py",
            "backend/app/ingestion/receivers/file.py",
            "backend/app/ingestion/receivers/http.py",
            "backend/app/ingestion/receivers/syslog.py",
            "backend/app/ingestion/receivers/tcp.py",
        ],
    )

    from app.ingestion.pipeline import IngestionPipeline

    assert IngestionPipeline is not None

    print(
        "Collection / receiver / queue / retry / "
        "dead-letter / pipeline modules present."
    )

    print("[PASS] Phase 04")


# =============================================================================
# PHASE 05
# =============================================================================


def validate_phase05() -> None:
    banner(
        "PHASE 05 — PARSING, NORMALIZATION & ENRICHMENT"
    )

    require_files(
        5,
        [
            "backend/app/parsing/__init__.py",
            "backend/app/parsing/pipeline.py",
            "backend/app/parsing/registry.py",
            "backend/app/parsing/parsers/__init__.py",
            "backend/app/parsing/normalizers/__init__.py",
            "backend/app/parsing/enrichers/__init__.py",
        ],
    )

    from app.parsing.pipeline import ParsingPipeline
    from app.parsing.registry import (
        EnricherRegistry,
        NormalizerRegistry,
        ParserRegistry,
    )

    assert ParsingPipeline is not None
    assert ParserRegistry is not None
    assert NormalizerRegistry is not None
    assert EnricherRegistry is not None

    print(
        "Parser → Normalizer → Canonicalizer → "
        "Enricher pipeline surface present."
    )

    print("[PASS] Phase 05")


# =============================================================================
# PHASE 06
# =============================================================================


def validate_phase06() -> None:
    banner(
        "PHASE 06 — STORAGE & SEARCH"
    )

    require_files(
        6,
        [
            "backend/app/storage/__init__.py",
            "backend/app/storage/migrations/001_storage_metadata.sql",
            "backend/app/storage/opensearch/__init__.py",
            "backend/app/storage/opensearch/client.py",
            "backend/app/storage/opensearch/events.py",
            "backend/app/storage/postgres/__init__.py",
            "backend/app/storage/postgres/models.py",
            "backend/app/storage/postgres/repository.py",
            "backend/app/storage/postgres/session.py",
            "backend/app/storage/redis/__init__.py",
            "backend/app/storage/redis/client.py",
            "backend/app/storage/redis/kv.py",
            "backend/app/storage/repositories/__init__.py",
            "backend/app/storage/repositories/events.py",
            "backend/app/storage/repositories/kv.py",
        ],
    )

    from app.storage.opensearch.events import (
        OpenSearchEventRepository,
    )

    from app.storage.redis.kv import (
        RedisKeyValueRepository,
    )

    assert OpenSearchEventRepository is not None
    assert RedisKeyValueRepository is not None

    print(
        "PostgreSQL / OpenSearch / Redis / repository "
        "modules present."
    )

    print("[PASS] Phase 06")


# =============================================================================
# PHASE 07 → 13
# =============================================================================


def run_real_integration_test(
    phase: int,
    filename: str,
) -> None:
    test_file = INTEGRATION / filename

    assert test_file.is_file(), (
        f"Phase {phase:02d} real integration test is missing: "
        f"{test_file}"
    )

    banner(
        f"PHASE {phase:02d} — REAL INTEGRATION TEST"
    )

    print(
        f"Test file : {test_file}"
    )

    print(
        f"Attacker  : {ATTACKER_IP}"
    )

    print(
        f"Target    : {TARGET_HOST}"
    )

    print(
        f"User      : {TARGET_USER}"
    )

    print(
        "Scenario  : SSH account compromise"
    )

    command = [
        sys.executable,
        "-m",
        "pytest",
        "-v",
        str(test_file),
        "-s",
    ]

    result = subprocess.run(
        command,
        cwd=PROJECT_ROOT,
        text=True,
        capture_output=True,
        check=False,
    )

    if result.stdout:
        print(result.stdout)

    if result.stderr:
        print(result.stderr)

    assert result.returncode == 0, (
        f"Phase {phase:02d} integration test failed:\n"
        f"{test_file}"
    )

    print(
        f"[PASS] Phase {phase:02d}"
    )


# =============================================================================
# MASTER TEST
# =============================================================================


def test_real_phase01_to_phase13_end_to_end() -> None:
    banner(
        "SENTINELSIEM — REAL PHASE 01 → 13 MASTER VALIDATION"
    )

    print(
        f"Project root   : {PROJECT_ROOT}"
    )

    print(
        f"Python         : {sys.executable}"
    )

    print(
        f"Integration dir: {INTEGRATION}"
    )

    print(
        f"Attacker       : {ATTACKER_IP}"
    )

    print(
        f"Target         : {TARGET_HOST}"
    )

    print(
        f"Target user    : {TARGET_USER}"
    )

    print(
        "Scenario       : SSH account compromise"
    )

    # -------------------------------------------------------------------------
    # Phase 01 → 06
    # -------------------------------------------------------------------------

    validate_phase01()
    validate_phase02()
    validate_phase03()
    validate_phase04()
    validate_phase05()
    validate_phase06()

    # -------------------------------------------------------------------------
    # Phase 07 → 13
    #
    # These are the existing real integration tests in this project.
    # -------------------------------------------------------------------------

    real_tests = [
        (7, "test_phase07_real_detection.py"),
        (8, "test_phase08_real_plugin.py"),
        (9, "test_phase09_real_correlation.py"),
        (10, "test_phase10_real_risk.py"),
        (11, "test_phase11_real_alert.py"),
        (12, "test_phase12_real_incident.py"),
        (13, "test_phase13_real_threat_intelligence.py"),
    ]

    for phase, filename in real_tests:
        run_real_integration_test(
            phase,
            filename,
        )

    # -------------------------------------------------------------------------
    # FINAL REPORT
    # -------------------------------------------------------------------------

    banner(
        "REAL PHASE 01 → 13 MASTER VALIDATION PASSED"
    )

    for phase in range(1, 14):
        print(
            f"[PASS] Phase {phase:02d}"
        )

    print()
    print("Attack scenario:")
    print(
        f"  Attacker : {ATTACKER_IP}"
    )
    print(
        f"  Target   : {TARGET_HOST}"
    )
    print(
        f"  User     : {TARGET_USER}"
    )
    print(
        "  Attack   : SSH account compromise"
    )

    print()
    print(
        "Phase 07 → 13 existing real integration tests "
        "executed successfully."
    )

    print(
        "Phase 01 → 06 current architecture/module surface "
        "validated successfully."
    )
