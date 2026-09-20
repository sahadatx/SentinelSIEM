"""
MITRE ATT&CK Enterprise STIX dataset importer.

The importer converts the official MITRE ATT&CK Enterprise STIX/JSON
dataset into SentinelSIEM's normalized PostgreSQL MITRE knowledge base.

Locked architecture
-------------------

    backend/data/mitre/enterprise-attack.json
                    │
                    ▼
              MitreImporter
                    │
        ┌───────────┼───────────────┐
        ▼           ▼               ▼
     Validate    Normalize       Extract
        │           │               │
        └───────────┼───────────────┘
                    ▼
                PostgreSQL
                    │
        ┌───────────┼─────────────────────┐
        ▼           ▼                     ▼
     Tactics    Techniques /          Relationships
                Sub-techniques
                    │
                    ▼
              Repository / Service
                    │
                    ▼
                  API / UI


Important architecture boundaries
---------------------------------

1. MITRE ATT&CK knowledge is dataset-backed.
2. The official MITRE dataset is the authoritative write source.
3. API/UI does not provide MITRE knowledge CRUD.
4. Re-running this importer must not create duplicate knowledge.
5. Existing knowledge is updated when the dataset changes.
6. Stale knowledge is removed during synchronization.
7. Detection → MITRE mappings are NOT imported here.
8. Detection → MITRE mappings remain owned by the SentinelSIEM
   detection/mapping subsystem.
9. The importer does not commit or rollback transactions.
10. Transaction ownership belongs to the caller/session manager.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession


logger = logging.getLogger(__name__)


# ============================================================================
# Constants
# ============================================================================

# importer.py:
#   backend/app/mitre/importer.py
#
# parents[0] -> backend/app/mitre
# parents[1] -> backend/app
# parents[2] -> backend
#
# Therefore the dataset is:
#   backend/data/mitre/enterprise-attack.json

PROJECT_ROOT = Path(__file__).resolve().parents[2]

DEFAULT_DATASET_PATH = (
    PROJECT_ROOT
    / "data"
    / "mitre"
    / "enterprise-attack.json"
)

DATASET_NAME = "enterprise-attack"

STIX_BUNDLE_TYPE = "bundle"

TACTIC_OBJECT_TYPE = "x-mitre-tactic"
TECHNIQUE_OBJECT_TYPE = "attack-pattern"
RELATIONSHIP_OBJECT_TYPE = "relationship"

TECHNIQUE_TYPE = "TECHNIQUE"
SUBTECHNIQUE_TYPE = "SUB_TECHNIQUE"

TACTIC_EXTERNAL_ID = re.compile(
    r"^TA\d{4}$",
)

TECHNIQUE_EXTERNAL_ID = re.compile(
    r"^T\d{4}$",
)

SUBTECHNIQUE_EXTERNAL_ID = re.compile(
    r"^T\d{4}\.\d{3}$",
)


# ============================================================================
# Import Result
# ============================================================================


@dataclass(slots=True, frozen=True)
class MitreImportResult:
    """Summary of one MITRE ATT&CK dataset import."""

    dataset_name: str

    dataset_version: str | None

    object_count: int

    tactic_count: int

    technique_count: int

    subtechnique_count: int

    platform_count: int

    relationship_count: int

    reference_count: int

    dataset_hash: str

    status: str = "SUCCESS"

    warnings: tuple[str, ...] = field(
        default_factory=tuple,
    )

    @property
    def total_knowledge_objects(self) -> int:
        """Return the number of normalized MITRE knowledge objects."""

        return (
            self.tactic_count
            + self.technique_count
            + self.subtechnique_count
            + self.platform_count
        )


# ============================================================================
# Internal Parsed Objects
# ============================================================================


@dataclass(slots=True, frozen=True)
class _ParsedTactic:
    """Normalized MITRE tactic."""

    external_id: str
    name: str
    description: str


@dataclass(slots=True, frozen=True)
class _ParsedTechnique:
    """Normalized MITRE technique or sub-technique."""

    external_id: str
    name: str
    description: str
    technique_type: str
    parent_external_id: str | None

    tactic_external_ids: tuple[str, ...]

    platform_names: tuple[str, ...]

    references: tuple[
        dict[str, str | None],
        ...
    ]


@dataclass(slots=True, frozen=True)
class _ParsedPlatform:
    """Normalized MITRE platform."""

    external_id: str
    name: str
    description: str = ""


@dataclass(slots=True, frozen=True)
class _ParsedRelationship:
    """Normalized STIX relationship."""

    external_id: str
    relationship_type: str
    source_external_id: str
    target_external_id: str
    description: str


# ============================================================================
# Exceptions
# ============================================================================


class MitreImportError(RuntimeError):
    """Raised when MITRE ATT&CK import fails."""


class MitreDatasetError(MitreImportError):
    """Raised when the MITRE dataset is invalid or unsupported."""


# ============================================================================
# Utility Functions
# ============================================================================


def _clean_text(
    value: Any,
) -> str:
    """Convert arbitrary input into normalized text."""

    if value is None:
        return ""

    return str(value).strip()


def _extract_external_id(
    obj: dict[str, Any],
) -> str | None:
    """
    Extract a valid ATT&CK external ID from a STIX object.

    Supported:
        TA0001
        T1059
        T1059.001
    """

    references = obj.get(
        "external_references",
    )

    if not isinstance(
        references,
        list,
    ):
        return None

    for reference in references:
        if not isinstance(
            reference,
            dict,
        ):
            continue

        external_id = reference.get(
            "external_id",
        )

        if not isinstance(
            external_id,
            str,
        ):
            continue

        external_id = external_id.strip()

        if (
            TACTIC_EXTERNAL_ID.fullmatch(
                external_id,
            )
            or TECHNIQUE_EXTERNAL_ID.fullmatch(
                external_id,
            )
            or SUBTECHNIQUE_EXTERNAL_ID.fullmatch(
                external_id,
            )
        ):
            return external_id

    return None


def _extract_name(
    obj: dict[str, Any],
) -> str:
    """Extract and normalize a STIX object name."""

    return _clean_text(
        obj.get("name"),
    )


def _extract_description(
    obj: dict[str, Any],
) -> str:
    """Extract and normalize a STIX object description."""

    return _clean_text(
        obj.get("description"),
    )


def _platform_external_id(
    name: str,
) -> str:
    """
    Generate a deterministic platform external ID.

    Example:

        Windows       -> windows
        Linux         -> linux
        macOS         -> macos
        Network Devices -> network-devices
    """

    normalized = _clean_text(
        name,
    ).lower()

    normalized = re.sub(
        r"[^a-z0-9]+",
        "-",
        normalized,
    )

    normalized = normalized.strip(
        "-",
    )

    if not normalized:
        raise MitreDatasetError(
            "MITRE platform name cannot produce an empty identifier.",
        )

    return normalized


def _dataset_version(
    bundle: dict[str, Any],
) -> str | None:
    """
    Extract the best available dataset version.

    MITRE/STIX bundles can expose version information differently depending
    on the release format. Several known locations are therefore checked.
    """

    # ------------------------------------------------------------------------
    # Bundle-level metadata
    # ------------------------------------------------------------------------

    for key in (
        "version",
        "x_mitre_version",
        "x_mitre_attack_version",
        "modified",
    ):
        value = bundle.get(
            key,
        )

        if value:
            return _clean_text(
                value,
            )

    # ------------------------------------------------------------------------
    # Object-level metadata
    # ------------------------------------------------------------------------

    objects = bundle.get(
        "objects",
    )

    if not isinstance(
        objects,
        list,
    ):
        return None

    versions: set[str] = set()

    for obj in objects:
        if not isinstance(
            obj,
            dict,
        ):
            continue

        for key in (
            "x_mitre_version",
            "x_mitre_attack_version",
        ):
            value = obj.get(
                key,
            )

            if value:
                normalized = _clean_text(
                    value,
                )

                if normalized:
                    versions.add(
                        normalized,
                    )

    if not versions:
        return None

    return sorted(
        versions,
    )[-1]


def _dataset_hash(
    path: Path,
) -> str:
    """Calculate SHA-256 hash of the source dataset."""

    digest = hashlib.sha256()

    try:
        with path.open(
            "rb",
        ) as file:
            for chunk in iter(
                lambda: file.read(
                    1024 * 1024,
                ),
                b"",
            ):
                digest.update(
                    chunk,
                )

    except OSError as exc:
        raise MitreDatasetError(
            (
                "Unable to calculate dataset hash: "
                f"{path}"
            ),
        ) from exc

    return digest.hexdigest()


def _is_revoked_or_deprecated(
    obj: dict[str, Any],
) -> bool:
    """
    Return True when a STIX object should not be imported.

    Revoked and deprecated ATT&CK objects are excluded from current
    authoritative knowledge.
    """

    if obj.get(
        "revoked",
    ) is True:
        return True

    if obj.get(
        "x_mitre_deprecated",
    ) is True:
        return True

    return False


def _relationship_description(
    relationship: dict[str, Any],
) -> str:
    """Extract relationship description."""

    return _clean_text(
        relationship.get(
            "description",
        ),
    )


# ============================================================================
# MITRE Importer
# ============================================================================


class MitreImporter:
    """
    Import the official MITRE ATT&CK Enterprise STIX dataset.

    The importer owns MITRE knowledge synchronization only.

    It deliberately does not own:
        - Detection → MITRE mappings
        - coverage persistence
        - API/UI CRUD
        - database commit
        - database rollback
    """

    def __init__(
        self,
        session: AsyncSession,
        dataset_path: Path | str | None = None,
    ) -> None:
        self.session = session

        self.dataset_path = Path(
            dataset_path
            if dataset_path is not None
            else DEFAULT_DATASET_PATH,
        ).expanduser().resolve()

    # ========================================================================
    # Public API
    # ========================================================================

    async def import_dataset(
        self,
    ) -> MitreImportResult:
        """
        Import and synchronize the complete Enterprise ATT&CK dataset.

        Transaction ownership remains with the caller.

        Processing order:

            Load
              ↓
            Validate
              ↓
            Parse
              ↓
            Upsert tactics
              ↓
            Upsert platforms
              ↓
            Upsert techniques
              ↓
            Resolve parents
              ↓
            Sync technique ↔ tactic
              ↓
            Sync technique ↔ platform
              ↓
            Sync references
              ↓
            Sync STIX relationships
              ↓
            Remove stale knowledge
              ↓
            Record import
        """

        logger.info(
            "Starting MITRE ATT&CK import from %s",
            self.dataset_path,
        )

        # --------------------------------------------------------------------
        # Load source dataset
        # --------------------------------------------------------------------

        bundle = self._load_dataset()

        dataset_hash = _dataset_hash(
            self.dataset_path,
        )

        # --------------------------------------------------------------------
        # Validate source bundle
        # --------------------------------------------------------------------

        objects = self._validate_bundle(
            bundle,
        )

        # --------------------------------------------------------------------
        # Parse source objects
        # --------------------------------------------------------------------

        parsed = self._parse_objects(
            objects,
        )

        tactics: list[_ParsedTactic] = parsed[
            "tactics"
        ]

        techniques: list[_ParsedTechnique] = parsed[
            "techniques"
        ]

        platforms: list[_ParsedPlatform] = parsed[
            "platforms"
        ]

        relationships: list[_ParsedRelationship] = parsed[
            "relationships"
        ]

        warnings: list[str] = parsed[
            "warnings"
        ]

        try:
            # ---------------------------------------------------------------
            # Tactics
            # ---------------------------------------------------------------

            await self._upsert_tactics(
                tactics,
            )

            # ---------------------------------------------------------------
            # Platforms
            # ---------------------------------------------------------------

            await self._upsert_platforms(
                platforms,
            )

            # ---------------------------------------------------------------
            # Techniques / sub-techniques
            # ---------------------------------------------------------------

            await self._upsert_techniques(
                techniques,
            )

            # ---------------------------------------------------------------
            # Parent UUID resolution
            # ---------------------------------------------------------------

            await self._resolve_technique_parents(
                techniques,
            )

            # ---------------------------------------------------------------
            # Technique ↔ Tactic
            # ---------------------------------------------------------------

            await self._sync_technique_tactics(
                techniques,
            )

            # ---------------------------------------------------------------
            # Technique ↔ Platform
            # ---------------------------------------------------------------

            await self._sync_technique_platforms(
                techniques,
            )

            # ---------------------------------------------------------------
            # References
            # ---------------------------------------------------------------

            await self._sync_references(
                techniques,
            )

            # ---------------------------------------------------------------
            # STIX relationships
            # ---------------------------------------------------------------

            await self._sync_relationships(
                relationships,
            )

            # ---------------------------------------------------------------
            # Remove stale knowledge
            # ---------------------------------------------------------------

            await self._cleanup_stale_knowledge(
                active_technique_ids={
                    item.external_id
                    for item in techniques
                },
                active_tactic_ids={
                    item.external_id
                    for item in tactics
                },
                active_platform_ids={
                    item.external_id
                    for item in platforms
                },
            )

            # ---------------------------------------------------------------
            # Import result
            # ---------------------------------------------------------------

            result = MitreImportResult(
                dataset_name=DATASET_NAME,
                dataset_version=_dataset_version(
                    bundle,
                ),
                object_count=len(objects),
                tactic_count=len(tactics),
                technique_count=sum(
                    item.technique_type
                    == TECHNIQUE_TYPE
                    for item in techniques
                ),
                subtechnique_count=sum(
                    item.technique_type
                    == SUBTECHNIQUE_TYPE
                    for item in techniques
                ),
                platform_count=len(platforms),
                relationship_count=len(
                    relationships,
                ),
                reference_count=sum(
                    len(item.references)
                    for item in techniques
                ),
                dataset_hash=dataset_hash,
                status="SUCCESS",
                warnings=tuple(
                    warnings,
                ),
            )

            # ---------------------------------------------------------------
            # Import history
            # ---------------------------------------------------------------

            await self._record_import(
                result,
            )

        except Exception as exc:
            logger.exception(
                "MITRE ATT&CK import failed.",
            )

            raise MitreImportError(
                "MITRE ATT&CK dataset import failed.",
            ) from exc

        logger.info(
            (
                "MITRE ATT&CK import completed successfully: "
                "%d tactics, %d techniques, "
                "%d sub-techniques, %d platforms, "
                "%d relationships, %d references."
            ),
            result.tactic_count,
            result.technique_count,
            result.subtechnique_count,
            result.platform_count,
            result.relationship_count,
            result.reference_count,
        )

        if result.warnings:
            logger.warning(
                (
                    "MITRE import completed with %d warnings."
                ),
                len(
                    result.warnings,
                ),
            )

        return result

    # ========================================================================
    # Dataset Loading
    # ========================================================================

    def _load_dataset(
        self,
    ) -> dict[str, Any]:
        """Load the source STIX JSON dataset."""

        if not self.dataset_path.exists():
            raise MitreDatasetError(
                (
                    "MITRE dataset not found: "
                    f"{self.dataset_path}"
                ),
            )

        if not self.dataset_path.is_file():
            raise MitreDatasetError(
                (
                    "MITRE dataset path is not a file: "
                    f"{self.dataset_path}"
                ),
            )

        try:
            with self.dataset_path.open(
                "r",
                encoding="utf-8",
            ) as file:
                data = json.load(
                    file,
                )

        except json.JSONDecodeError as exc:
            raise MitreDatasetError(
                (
                    "MITRE dataset contains invalid JSON: "
                    f"{self.dataset_path}"
                ),
            ) from exc

        except OSError as exc:
            raise MitreDatasetError(
                (
                    "Unable to read MITRE dataset: "
                    f"{self.dataset_path}"
                ),
            ) from exc

        if not isinstance(
            data,
            dict,
        ):
            raise MitreDatasetError(
                "MITRE dataset root must be a JSON object.",
            )

        return data

    # ========================================================================
    # Bundle Validation
    # ========================================================================

    def _validate_bundle(
        self,
        bundle: dict[str, Any],
    ) -> list[dict[str, Any]]:
        """Validate the minimum required STIX bundle structure."""

        if bundle.get(
            "type",
        ) != STIX_BUNDLE_TYPE:
            raise MitreDatasetError(
                (
                    "Unsupported MITRE dataset type: "
                    f"{bundle.get('type')!r}. "
                    "Expected 'bundle'."
                ),
            )

        objects = bundle.get(
            "objects",
        )

        if not isinstance(
            objects,
            list,
        ):
            raise MitreDatasetError(
                "MITRE dataset 'objects' must be a list.",
            )

        if not objects:
            raise MitreDatasetError(
                "MITRE dataset contains no STIX objects.",
            )

        valid_objects: list[
            dict[str, Any]
        ] = []

        for index, obj in enumerate(
            objects,
        ):
            if not isinstance(
                obj,
                dict,
            ):
                raise MitreDatasetError(
                    (
                        "MITRE dataset object at index "
                        f"{index} is not a JSON object."
                    ),
                )

            object_type = obj.get(
                "type",
            )

            if not isinstance(
                object_type,
                str,
            ):
                continue

            valid_objects.append(
                obj,
            )

        if not valid_objects:
            raise MitreDatasetError(
                "MITRE dataset contains no valid STIX objects.",
            )

        return valid_objects

    # ========================================================================
    # Object Parsing
    # ========================================================================

    def _parse_objects(
        self,
        objects: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """
        Parse relevant STIX objects.

        Returns:

            tactics
            techniques
            platforms
            relationships
            warnings
        """

        tactics: list[
            _ParsedTactic
        ] = []

        techniques: list[
            _ParsedTechnique
        ] = []

        relationships: list[
            _ParsedRelationship
        ] = []

        platform_names: set[str] = set()

        warnings: list[str] = []

        tactic_name_to_id: dict[
            str,
            str,
        ] = {}

        # --------------------------------------------------------------------
        # Tactics
        # --------------------------------------------------------------------

        for obj in objects:
            if obj.get(
                "type",
            ) != TACTIC_OBJECT_TYPE:
                continue

            if _is_revoked_or_deprecated(
                obj,
            ):
                continue

            external_id = _extract_external_id(
                obj,
            )

            name = _extract_name(
                obj,
            )

            if external_id is None:
                warnings.append(
                    (
                        "Skipped tactic without valid external ID: "
                        f"{obj.get('id', '<unknown>')}"
                    ),
                )
                continue

            if not TACTIC_EXTERNAL_ID.fullmatch(
                external_id,
            ):
                warnings.append(
                    (
                        "Skipped invalid tactic ID: "
                        f"{external_id}"
                    ),
                )
                continue

            if not name:
                warnings.append(
                    (
                        "Skipped tactic without name: "
                        f"{external_id}"
                    ),
                )
                continue

            tactic = _ParsedTactic(
                external_id=external_id,
                name=name,
                description=_extract_description(
                    obj,
                ),
            )

            tactics.append(
                tactic,
            )

            tactic_name_to_id[
                name.casefold()
            ] = external_id

        # --------------------------------------------------------------------
        # Techniques and sub-techniques
        # --------------------------------------------------------------------

        for obj in objects:
            if obj.get(
                "type",
            ) != TECHNIQUE_OBJECT_TYPE:
                continue

            if _is_revoked_or_deprecated(
                obj,
            ):
                continue

            external_id = _extract_external_id(
                obj,
            )

            name = _extract_name(
                obj,
            )

            if external_id is None:
                warnings.append(
                    (
                        "Skipped attack-pattern without valid "
                        "external ID: "
                        f"{obj.get('id', '<unknown>')}"
                    ),
                )
                continue

            if not (
                TECHNIQUE_EXTERNAL_ID.fullmatch(
                    external_id,
                )
                or SUBTECHNIQUE_EXTERNAL_ID.fullmatch(
                    external_id,
                )
            ):
                warnings.append(
                    (
                        "Skipped unsupported attack-pattern ID: "
                        f"{external_id}"
                    ),
                )
                continue

            if not name:
                warnings.append(
                    (
                        "Skipped technique without name: "
                        f"{external_id}"
                    ),
                )
                continue

            is_subtechnique = bool(
                SUBTECHNIQUE_EXTERNAL_ID.fullmatch(
                    external_id,
                ),
            )

            parent_external_id: str | None = None

            if is_subtechnique:
                parent_external_id = (
                    external_id.split(
                        ".",
                        1,
                    )[0]
                )

            tactic_external_ids = (
                self._extract_tactic_ids(
                    obj,
                    tactic_name_to_id,
                )
            )

            platform_values = (
                self._extract_platforms(
                    obj,
                )
            )

            platform_names.update(
                platform_values,
            )

            references = (
                self._extract_references(
                    obj,
                )
            )

            techniques.append(
                _ParsedTechnique(
                    external_id=external_id,
                    name=name,
                    description=_extract_description(
                        obj,
                    ),
                    technique_type=(
                        SUBTECHNIQUE_TYPE
                        if is_subtechnique
                        else TECHNIQUE_TYPE
                    ),
                    parent_external_id=parent_external_id,
                    tactic_external_ids=tactic_external_ids,
                    platform_names=platform_values,
                    references=references,
                ),
            )

        # --------------------------------------------------------------------
        # Platforms
        # --------------------------------------------------------------------

        platforms: list[
            _ParsedPlatform
        ] = []

        for name in sorted(
            platform_names,
            key=str.casefold,
        ):
            platforms.append(
                _ParsedPlatform(
                    external_id=_platform_external_id(
                        name,
                    ),
                    name=name,
                ),
            )

        # --------------------------------------------------------------------
        # STIX relationships
        # --------------------------------------------------------------------

        for obj in objects:
            if obj.get(
                "type",
            ) != RELATIONSHIP_OBJECT_TYPE:
                continue

            if _is_revoked_or_deprecated(
                obj,
            ):
                continue

            relationship_id = _clean_text(
                obj.get(
                    "id",
                ),
            )

            source_id = _clean_text(
                obj.get(
                    "source_ref",
                ),
            )

            target_id = _clean_text(
                obj.get(
                    "target_ref",
                ),
            )

            relationship_type = _clean_text(
                obj.get(
                    "relationship_type",
                ),
            )

            if not relationship_id:
                warnings.append(
                    "Skipped relationship without STIX ID.",
                )
                continue

            if not source_id:
                warnings.append(
                    (
                        "Skipped relationship without source: "
                        f"{relationship_id}"
                    ),
                )
                continue

            if not target_id:
                warnings.append(
                    (
                        "Skipped relationship without target: "
                        f"{relationship_id}"
                    ),
                )
                continue

            if not relationship_type:
                warnings.append(
                    (
                        "Skipped relationship without type: "
                        f"{relationship_id}"
                    ),
                )
                continue

            relationships.append(
                _ParsedRelationship(
                    external_id=relationship_id,
                    relationship_type=relationship_type,
                    source_external_id=source_id,
                    target_external_id=target_id,
                    description=_relationship_description(
                        obj,
                    ),
                ),
            )

        # --------------------------------------------------------------------
        # Deterministic ordering
        # --------------------------------------------------------------------

        tactics.sort(
            key=lambda item: item.external_id,
        )

        techniques.sort(
            key=lambda item: item.external_id,
        )

        platforms.sort(
            key=lambda item: item.external_id,
        )

        relationships.sort(
            key=lambda item: item.external_id,
        )

        return {
            "tactics": tactics,
            "techniques": techniques,
            "platforms": platforms,
            "relationships": relationships,
            "warnings": warnings,
        }

    # ========================================================================
    # Tactic Extraction
    # ========================================================================

    def _extract_tactic_ids(
        self,
        obj: dict[str, Any],
        tactic_name_to_id: dict[str, str],
    ) -> tuple[str, ...]:
        """
        Extract MITRE tactic IDs from kill_chain_phases.

        Example:

            execution
            persistence
            privilege-escalation
            credential-access
        """

        phases = obj.get(
            "kill_chain_phases",
        )

        if not isinstance(
            phases,
            list,
        ):
            return ()

        tactic_ids: list[str] = []

        for phase in phases:
            if not isinstance(
                phase,
                dict,
            ):
                continue

            kill_chain_name = _clean_text(
                phase.get(
                    "kill_chain_name",
                ),
            )

            if kill_chain_name != "mitre-attack":
                continue

            phase_name = _clean_text(
                phase.get(
                    "phase_name",
                ),
            )

            if not phase_name:
                continue

            normalized_name = (
                phase_name
                .replace(
                    "-",
                    " ",
                )
                .casefold()
            )

            tactic_id = tactic_name_to_id.get(
                normalized_name,
            )

            if tactic_id is not None:
                tactic_ids.append(
                    tactic_id,
                )

        return tuple(
            dict.fromkeys(
                tactic_ids,
            ),
        )

    # ========================================================================
    # Platform Extraction
    # ========================================================================

    def _extract_platforms(
        self,
        obj: dict[str, Any],
    ) -> tuple[str, ...]:
        """
        Extract ATT&CK platforms from x_mitre_platforms.

        MITRE represents platforms on attack-pattern objects rather than
        requiring a standalone STIX platform object.
        """

        platforms = obj.get(
            "x_mitre_platforms",
        )

        if not isinstance(
            platforms,
            list,
        ):
            return ()

        normalized: list[str] = []

        for platform in platforms:
            value = _clean_text(
                platform,
            )

            if value:
                normalized.append(
                    value,
                )

        return tuple(
            dict.fromkeys(
                normalized,
            ),
        )

    # ========================================================================
    # Reference Extraction
    # ========================================================================

    def _extract_references(
        self,
        obj: dict[str, Any],
    ) -> tuple[
        dict[str, str | None],
        ...
    ]:
        """
        Extract external references from an ATT&CK object.

        This intentionally preserves all external references, including
        ATT&CK references and external documentation references.
        """

        references = obj.get(
            "external_references",
        )

        if not isinstance(
            references,
            list,
        ):
            return ()

        result: list[
            dict[str, str | None]
        ] = []

        for reference in references:
            if not isinstance(
                reference,
                dict,
            ):
                continue

            source_name = _clean_text(
                reference.get(
                    "source_name",
                ),
            )

            if not source_name:
                continue

            url = (
                _clean_text(
                    reference.get(
                        "url",
                    ),
                )
                or None
            )

            external_id = (
                _clean_text(
                    reference.get(
                        "external_id",
                    ),
                )
                or None
            )

            description = _clean_text(
                reference.get(
                    "description",
                ),
            )

            result.append(
                {
                    "source_name": source_name,
                    "url": url,
                    "external_id": external_id,
                    "description": description,
                },
            )

        return tuple(
            result,
        )

    # ========================================================================
    # Tactic UPSERT
    # ========================================================================

    async def _upsert_tactics(
        self,
        tactics: list[_ParsedTactic],
    ) -> None:
        """Insert or update all imported tactics."""

        if not tactics:
            return

        statement = text(
            """
            INSERT INTO siem_mitre_tactics (
                external_id,
                name,
                description,
                created_at,
                updated_at
            )
            VALUES (
                :external_id,
                :name,
                :description,
                NOW(),
                NOW()
            )
            ON CONFLICT (external_id)
            DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                updated_at = NOW()
            """
        )

        for tactic in tactics:
            await self.session.execute(
                statement,
                {
                    "external_id": tactic.external_id,
                    "name": tactic.name,
                    "description": tactic.description,
                },
            )

    # ========================================================================
    # Platform UPSERT
    # ========================================================================

    async def _upsert_platforms(
        self,
        platforms: list[_ParsedPlatform],
    ) -> None:
        """Insert or update all imported platforms."""

        if not platforms:
            return

        statement = text(
            """
            INSERT INTO siem_mitre_platforms (
                external_id,
                name,
                description,
                created_at,
                updated_at
            )
            VALUES (
                :external_id,
                :name,
                :description,
                NOW(),
                NOW()
            )
            ON CONFLICT (external_id)
            DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                updated_at = NOW()
            """
        )

        for platform in platforms:
            await self.session.execute(
                statement,
                {
                    "external_id": platform.external_id,
                    "name": platform.name,
                    "description": platform.description,
                },
            )

    # ========================================================================
    # Technique UPSERT
    # ========================================================================

    async def _upsert_techniques(
        self,
        techniques: list[_ParsedTechnique],
    ) -> None:
        """
        Insert or update all techniques and sub-techniques.

        Top-level techniques are inserted first so their UUIDs exist.
        Sub-techniques are then inserted with parent_id resolved directly
        from the parent's external_id.

        This preserves the database constraint that every SUB_TECHNIQUE
        must have a non-NULL parent_id.
        """

        if not techniques:
            return

        # ---------------------------------------------------------------
        # Pass 1: Top-level techniques
        # ---------------------------------------------------------------

        top_level_statement = text(
            """
            INSERT INTO siem_mitre_techniques (
                external_id,
                name,
                description,
                type,
                parent_id,
                created_at,
                updated_at
            )
            VALUES (
                :external_id,
                :name,
                :description,
                'TECHNIQUE',
                NULL,
                NOW(),
                NOW()
            )
            ON CONFLICT (external_id)
            DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                type = EXCLUDED.type,
                parent_id = NULL,
                updated_at = NOW()
            """
        )

        top_level = [
            technique
            for technique in techniques
            if technique.technique_type == TECHNIQUE_TYPE
        ]

        for technique in top_level:
            await self.session.execute(
                top_level_statement,
                {
                    "external_id": technique.external_id,
                    "name": technique.name,
                    "description": technique.description,
                },
            )

        # ---------------------------------------------------------------
        # Pass 2: Sub-techniques
        # ---------------------------------------------------------------

        subtechnique_statement = text(
            """
            INSERT INTO siem_mitre_techniques (
                external_id,
                name,
                description,
                type,
                parent_id,
                created_at,
                updated_at
            )
            VALUES (
                :external_id,
                :name,
                :description,
                'SUB_TECHNIQUE',
                (
                    SELECT id
                    FROM siem_mitre_techniques
                    WHERE external_id = :parent_external_id
                      AND type = 'TECHNIQUE'
                ),
                NOW(),
                NOW()
            )
            ON CONFLICT (external_id)
            DO UPDATE SET
                name = EXCLUDED.name,
                description = EXCLUDED.description,
                type = EXCLUDED.type,
                parent_id = EXCLUDED.parent_id,
                updated_at = NOW()
            """
        )

        subtechniques = [
            technique
            for technique in techniques
            if technique.technique_type == SUBTECHNIQUE_TYPE
        ]

        missing_parents: list[str] = []

        for technique in subtechniques:
            if not technique.parent_external_id:
                missing_parents.append(
                    f"{technique.external_id}: missing parent external ID"
                )
                continue

            parent_exists = await self.session.scalar(
                text(
                    """
                    SELECT id
                    FROM siem_mitre_techniques
                    WHERE external_id = :parent_external_id
                      AND type = 'TECHNIQUE'
                    """
                ),
                {
                    "parent_external_id": technique.parent_external_id,
                },
            )

            if parent_exists is None:
                missing_parents.append(
                    f"{technique.external_id}: "
                    f"parent {technique.parent_external_id} not found"
                )
                continue

            await self.session.execute(
                subtechnique_statement,
                {
                    "external_id": technique.external_id,
                    "name": technique.name,
                    "description": technique.description,
                    "parent_external_id": technique.parent_external_id,
                },
            )

        if missing_parents:
            preview = "; ".join(missing_parents[:10])
            extra = len(missing_parents) - min(len(missing_parents), 10)

            message = (
                "MITRE sub-techniques with unresolved parents: "
                f"{preview}"
            )

            if extra > 0:
                message += f"; ... and {extra} more"

            raise MitreDatasetError(message)

    # ===============================================================
    # Parent Resolution
    # ===============================================================
    # Parent Resolution
    # ========================================================================

    async def _resolve_technique_parents(
        self,
        techniques: list[_ParsedTechnique],
    ) -> None:
        """
        Resolve sub-technique parent UUIDs.

        PostgreSQL schema:

            siem_mitre_techniques.parent_id
                → UUID
                → siem_mitre_techniques.id

        Dataset/domain:

            T1059.001
                → parent T1059

        This method converts the external parent relationship into the
        database UUID foreign key.
        """

        # --------------------------------------------------------------------
        # Clear parent IDs for top-level techniques.
        # --------------------------------------------------------------------

        await self.session.execute(
            text(
                """
                UPDATE siem_mitre_techniques
                SET
                    parent_id = NULL,
                    updated_at = NOW()
                WHERE type = 'TECHNIQUE'
                """
            ),
        )

        # --------------------------------------------------------------------
        # Resolve sub-technique parents.
        # --------------------------------------------------------------------

        await self.session.execute(
            text(
                r"""
                UPDATE siem_mitre_techniques AS child
                SET
                    parent_id = parent.id,
                    updated_at = NOW()
                FROM siem_mitre_techniques AS parent
                WHERE child.type = 'SUB_TECHNIQUE'
                  AND child.external_id ~ '^T[0-9]{4}\.[0-9]{3}$'
                  AND parent.type = 'TECHNIQUE'
                  AND parent.external_id =
                        split_part(
                            child.external_id,
                            '.',
                            1
                        )
                """
            ),
        )

        # --------------------------------------------------------------------
        # Validate every imported sub-technique has a parent.
        # --------------------------------------------------------------------

        invalid_result = await self.session.execute(
            text(
                """
                SELECT external_id
                FROM siem_mitre_techniques
                WHERE type = 'SUB_TECHNIQUE'
                  AND parent_id IS NULL
                ORDER BY external_id
                """
            ),
        )

        invalid_ids = [
            str(row[0])
            for row in invalid_result.fetchall()
        ]

        if invalid_ids:
            preview = invalid_ids[:20]

            suffix = ""

            if len(invalid_ids) > 20:
                suffix = (
                    f" ... and {len(invalid_ids) - 20} more"
                )

            raise MitreDatasetError(
                (
                    "MITRE sub-techniques without valid parent "
                    "techniques: "
                    + ", ".join(preview)
                    + suffix
                ),
            )

    # ========================================================================
    # Technique ↔ Tactic Synchronization
    # ========================================================================

    async def _sync_technique_tactics(
        self,
        techniques: list[_ParsedTechnique],
    ) -> None:
        """
        Synchronize technique-to-tactic associations.

        The association table is authoritative for the current dataset.
        """

        await self.session.execute(
            text(
                """
                DELETE FROM siem_mitre_technique_tactics
                """
            ),
        )

        if not techniques:
            return

        statement = text(
            """
            INSERT INTO siem_mitre_technique_tactics (
                technique_id,
                tactic_id
            )
            SELECT
                technique.id,
                tactic.id
            FROM siem_mitre_techniques AS technique
            JOIN siem_mitre_tactics AS tactic
                ON tactic.external_id = :tactic_external_id
            WHERE technique.external_id =
                    :technique_external_id
            ON CONFLICT (
                technique_id,
                tactic_id
            )
            DO NOTHING
            """
        )

        for technique in techniques:
            for tactic_external_id in (
                technique.tactic_external_ids
            ):
                await self.session.execute(
                    statement,
                    {
                        "technique_external_id": (
                            technique.external_id
                        ),
                        "tactic_external_id": (
                            tactic_external_id
                        ),
                    },
                )

    # ========================================================================
    # Technique ↔ Platform Synchronization
    # ========================================================================

    async def _sync_technique_platforms(
        self,
        techniques: list[_ParsedTechnique],
    ) -> None:
        """
        Synchronize technique-to-platform associations.
        """

        await self.session.execute(
            text(
                """
                DELETE FROM siem_mitre_technique_platforms
                """
            ),
        )

        if not techniques:
            return

        statement = text(
            """
            INSERT INTO siem_mitre_technique_platforms (
                technique_id,
                platform_id
            )
            SELECT
                technique.id,
                platform.id
            FROM siem_mitre_techniques AS technique
            JOIN siem_mitre_platforms AS platform
                ON platform.external_id =
                    :platform_external_id
            WHERE technique.external_id =
                    :technique_external_id
            ON CONFLICT (
                technique_id,
                platform_id
            )
            DO NOTHING
            """
        )

        for technique in techniques:
            for platform_name in (
                technique.platform_names
            ):
                await self.session.execute(
                    statement,
                    {
                        "technique_external_id": (
                            technique.external_id
                        ),
                        "platform_external_id": (
                            _platform_external_id(
                                platform_name,
                            )
                        ),
                    },
                )

    # ========================================================================
    # Reference Synchronization
    # ========================================================================

    async def _sync_references(
        self,
        techniques: list[_ParsedTechnique],
    ) -> None:
        """
        Synchronize references for all imported techniques.

        References are owned by individual techniques in migration 008.
        """

        # --------------------------------------------------------------------
        # Remove references for all current techniques.
        #
        # This is simpler and deterministic for a complete authoritative
        # dataset synchronization.
        # --------------------------------------------------------------------

        await self.session.execute(
            text(
                """
                DELETE FROM siem_mitre_references
                """
            ),
        )

        if not techniques:
            return

        statement = text(
            """
            INSERT INTO siem_mitre_references (
                technique_id,
                source_name,
                url,
                external_id,
                description,
                created_at
            )
            SELECT
                technique.id,
                :source_name,
                :url,
                :external_id,
                :description,
                NOW()
            FROM siem_mitre_techniques AS technique
            WHERE technique.external_id =
                    :technique_external_id
            """
        )

        for technique in techniques:
            for reference in (
                technique.references
            ):
                await self.session.execute(
                    statement,
                    {
                        "technique_external_id": (
                            technique.external_id
                        ),
                        "source_name": reference[
                            "source_name"
                        ],
                        "url": reference[
                            "url"
                        ],
                        "external_id": reference[
                            "external_id"
                        ],
                        "description": reference[
                            "description"
                        ],
                    },
                )

    # ========================================================================
    # STIX Relationship Synchronization
    # ========================================================================

    async def _sync_relationships(
        self,
        relationships: list[_ParsedRelationship],
    ) -> None:
        """
        Synchronize all STIX relationships.

        The original STIX relationship ID is retained as
        relationship_external_id.

        This guarantees deterministic re-import behavior.
        """

        # --------------------------------------------------------------------
        # Current dataset is authoritative.
        # --------------------------------------------------------------------

        await self.session.execute(
            text(
                """
                DELETE FROM siem_mitre_relationships
                """
            ),
        )

        if not relationships:
            return

        statement = text(
            """
            INSERT INTO siem_mitre_relationships (
                relationship_external_id,
                relationship_type,
                source_external_id,
                target_external_id,
                description,
                created_at,
                updated_at
            )
            VALUES (
                :relationship_external_id,
                :relationship_type,
                :source_external_id,
                :target_external_id,
                :description,
                NOW(),
                NOW()
            )
            ON CONFLICT (
                relationship_external_id
            )
            DO UPDATE SET
                relationship_type =
                    EXCLUDED.relationship_type,
                source_external_id =
                    EXCLUDED.source_external_id,
                target_external_id =
                    EXCLUDED.target_external_id,
                description =
                    EXCLUDED.description,
                updated_at = NOW()
            """
        )

        for relationship in relationships:
            await self.session.execute(
                statement,
                {
                    "relationship_external_id": (
                        relationship.external_id
                    ),
                    "relationship_type": (
                        relationship.relationship_type
                    ),
                    "source_external_id": (
                        relationship.source_external_id
                    ),
                    "target_external_id": (
                        relationship.target_external_id
                    ),
                    "description": (
                        relationship.description
                    ),
                },
            )

    # ========================================================================
    # Stale Knowledge Cleanup
    # ========================================================================

    async def _cleanup_stale_knowledge(
        self,
        *,
        active_technique_ids: set[str],
        active_tactic_ids: set[str],
        active_platform_ids: set[str],
    ) -> None:
        """
        Remove knowledge that no longer exists in the source dataset.

        This operation is limited strictly to MITRE knowledge tables.

        Detection → MITRE mappings are untouched.
        """

        # --------------------------------------------------------------------
        # Technique ↔ Tactic relationships
        # --------------------------------------------------------------------

        if active_technique_ids:
            await self.session.execute(
                text(
                    """
                    DELETE FROM
                        siem_mitre_technique_tactics AS relation
                    USING siem_mitre_techniques AS technique
                    WHERE relation.technique_id = technique.id
                      AND technique.external_id <> ALL(
                            CAST(
                                :active_ids AS text[]
                            )
                      )
                    """
                ),
                {
                    "active_ids": list(
                        active_technique_ids,
                    ),
                },
            )

        else:
            await self.session.execute(
                text(
                    """
                    DELETE FROM
                        siem_mitre_technique_tactics
                    """
                ),
            )

        # --------------------------------------------------------------------
        # Technique ↔ Platform relationships
        # --------------------------------------------------------------------

        if active_technique_ids:
            await self.session.execute(
                text(
                    """
                    DELETE FROM
                        siem_mitre_technique_platforms AS relation
                    USING siem_mitre_techniques AS technique
                    WHERE relation.technique_id = technique.id
                      AND technique.external_id <> ALL(
                            CAST(
                                :active_ids AS text[]
                            )
                      )
                    """
                ),
                {
                    "active_ids": list(
                        active_technique_ids,
                    ),
                },
            )

        else:
            await self.session.execute(
                text(
                    """
                    DELETE FROM
                        siem_mitre_technique_platforms
                    """
                ),
            )

        # --------------------------------------------------------------------
        # References
        # --------------------------------------------------------------------

        if active_technique_ids:
            await self.session.execute(
                text(
                    """
                    DELETE FROM siem_mitre_references AS reference
                    USING siem_mitre_techniques AS technique
                    WHERE reference.technique_id = technique.id
                      AND technique.external_id <> ALL(
                            CAST(
                                :active_ids AS text[]
                            )
                      )
                    """
                ),
                {
                    "active_ids": list(
                        active_technique_ids,
                    ),
                },
            )

        else:
            await self.session.execute(
                text(
                    """
                    DELETE FROM siem_mitre_references
                    """
                ),
            )

        # --------------------------------------------------------------------
        # Techniques
        # --------------------------------------------------------------------

        if active_technique_ids:
            await self.session.execute(
                text(
                    """
                    DELETE FROM siem_mitre_techniques
                    WHERE external_id <> ALL(
                        CAST(
                            :active_ids AS text[]
                        )
                    )
                    """
                ),
                {
                    "active_ids": list(
                        active_technique_ids,
                    ),
                },
            )

        else:
            await self.session.execute(
                text(
                    """
                    DELETE FROM siem_mitre_techniques
                    """
                ),
            )

        # --------------------------------------------------------------------
        # Tactics
        # --------------------------------------------------------------------

        if active_tactic_ids:
            await self.session.execute(
                text(
                    """
                    DELETE FROM siem_mitre_tactics
                    WHERE external_id <> ALL(
                        CAST(
                            :active_ids AS text[]
                        )
                    )
                    """
                ),
                {
                    "active_ids": list(
                        active_tactic_ids,
                    ),
                },
            )

        else:
            await self.session.execute(
                text(
                    """
                    DELETE FROM siem_mitre_tactics
                    """
                ),
            )

        # --------------------------------------------------------------------
        # Platforms
        # --------------------------------------------------------------------

        if active_platform_ids:
            await self.session.execute(
                text(
                    """
                    DELETE FROM siem_mitre_platforms
                    WHERE external_id <> ALL(
                        CAST(
                            :active_ids AS text[]
                        )
                    )
                    """
                ),
                {
                    "active_ids": list(
                        active_platform_ids,
                    ),
                },
            )

        else:
            await self.session.execute(
                text(
                    """
                    DELETE FROM siem_mitre_platforms
                    """
                ),
            )

    # ========================================================================
    # Import History
    # ========================================================================

    async def _record_import(
        self,
        result: MitreImportResult,
    ) -> None:
        """
        Record successful import metadata.

        The import history row participates in the same transaction as the
        knowledge synchronization.
        """

        await self.session.execute(
            text(
                """
                INSERT INTO siem_mitre_imports (
                    dataset_name,
                    dataset_version,
                    source_path,
                    object_count,
                    tactic_count,
                    technique_count,
                    subtechnique_count,
                    platform_count,
                    relationship_count,
                    reference_count,
                    imported_at,
                    status,
                    error_message
                )
                VALUES (
                    :dataset_name,
                    :dataset_version,
                    :source_path,
                    :object_count,
                    :tactic_count,
                    :technique_count,
                    :subtechnique_count,
                    :platform_count,
                    :relationship_count,
                    :reference_count,
                    NOW(),
                    :status,
                    NULL
                )
                """
            ),
            {
                "dataset_name": result.dataset_name,
                "dataset_version": result.dataset_version,
                "source_path": str(
                    self.dataset_path,
                ),
                "object_count": result.object_count,
                "tactic_count": result.tactic_count,
                "technique_count": result.technique_count,
                "subtechnique_count": result.subtechnique_count,
                "platform_count": result.platform_count,
                "relationship_count": result.relationship_count,
                "reference_count": result.reference_count,
                "status": result.status,
            },
        )


# ============================================================================
# Convenience API
# ============================================================================


async def import_mitre_dataset(
    session: AsyncSession,
    dataset_path: Path | str | None = None,
) -> MitreImportResult:
    """
    Import the Enterprise ATT&CK dataset.

    Transaction ownership remains with the caller.
    """

    importer = MitreImporter(
        session=session,
        dataset_path=dataset_path,
    )

    return await importer.import_dataset()


# ============================================================================
# Public API
# ============================================================================


__all__ = [
    "DEFAULT_DATASET_PATH",
    "DATASET_NAME",
    "MitreDatasetError",
    "MitreImportError",
    "MitreImportResult",
    "MitreImporter",
    "import_mitre_dataset",
]
