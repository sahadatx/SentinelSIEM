"""
PostgreSQL repository for the MITRE ATT&CK knowledge base.

This repository is responsible only for persistence and retrieval of
MITRE ATT&CK knowledge.

Architecture
------------

    Official MITRE ATT&CK Dataset
                │
                ▼
             Importer
                │
                ▼
           PostgreSQL
                │
                ▼
       MitreRepository
                │
                ▼
          MitreService
                │
                ▼
              API/UI


Important boundary
------------------
MITRE ATT&CK knowledge and SentinelSIEM Detection → MITRE mappings are
separate concerns.

MITRE knowledge is dataset-owned and read-only from the API/UI perspective.

Detection → MITRE mappings are intentionally NOT stored in this repository.
They remain part of the existing SentinelSIEM mapping/coverage subsystem.

Transaction ownership
---------------------
This repository never commits or rolls back transactions.

The caller/application layer owns the transaction boundary.
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from sqlalchemy import delete, func, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.mitre.models import (
    MitreReference,
    MitreSubTechnique,
    MitreTactic,
    MitreTechnique,
)


# ============================================================================
# Exceptions
# ============================================================================


class MitreRepositoryError(RuntimeError):
    """Base exception for MITRE repository failures."""


class MitreNotFoundError(MitreRepositoryError):
    """Raised when a requested MITRE knowledge object does not exist."""


# ============================================================================
# Repository
# ============================================================================


class MitreRepository:
    """
    Async PostgreSQL repository for MITRE ATT&CK knowledge.

    Persistence concerns:
        - tactics
        - techniques
        - sub-techniques
        - platforms
        - tactic relationships
        - platform relationships
        - references
        - STIX relationships

    Explicitly excluded:
        - Detection → MITRE mappings
        - coverage state persistence
        - detection management
    """

    def __init__(
        self,
        session: AsyncSession,
    ) -> None:
        self.session = session

    # ========================================================================
    # Tactics
    # ========================================================================

    async def list_tactics(
        self,
        *,
        limit: int | None = None,
        offset: int = 0,
    ) -> list[MitreTactic]:
        """
        Return MITRE tactics ordered by external ID.
        """

        from app.storage.postgres.models import MitreTacticModel

        statement = (
            select(MitreTacticModel)
            .order_by(
                MitreTacticModel.external_id.asc(),
            )
        )

        normalized_offset = max(0, offset)

        if normalized_offset:
            statement = statement.offset(
                normalized_offset,
            )

        if limit is not None:
            normalized_limit = max(1, limit)

            statement = statement.limit(
                normalized_limit,
            )

        result = await self.session.execute(
            statement,
        )

        rows = result.scalars().all()

        return [
            self._tactic_domain(row)
            for row in rows
        ]

    async def get_tactic(
        self,
        tactic_id: str,
    ) -> MitreTactic | None:
        """
        Return one tactic by MITRE external ID.

        Example:
            TA0001
        """

        from app.storage.postgres.models import MitreTacticModel

        normalized_id = tactic_id.strip()

        statement = (
            select(MitreTacticModel)
            .where(
                MitreTacticModel.external_id
                == normalized_id,
            )
        )

        result = await self.session.execute(
            statement,
        )

        row = result.scalar_one_or_none()

        if row is None:
            return None

        return self._tactic_domain(row)

    async def count_tactics(self) -> int:
        """Return the total number of imported MITRE tactics."""

        from app.storage.postgres.models import MitreTacticModel

        result = await self.session.execute(
            select(
                func.count(
                    MitreTacticModel.id,
                ),
            ),
        )

        return int(
            result.scalar_one(),
        )

    # ========================================================================
    # Platforms
    # ========================================================================

    async def list_platforms(
        self,
    ) -> list[str]:
        """
        Return unique imported MITRE platform names.

        The public domain currently represents platform IDs as strings, while
        the database stores a normalized platform record with UUID PK and
        external_id/name fields.
        """

        from app.storage.postgres.models import MitrePlatformModel

        statement = (
            select(
                MitrePlatformModel.name,
            )
            .distinct()
            .order_by(
                MitrePlatformModel.name.asc(),
            )
        )

        result = await self.session.execute(
            statement,
        )

        return [
            str(value)
            for value in result.scalars().all()
            if value is not None
        ]

    async def list_platform_objects(
        self,
    ) -> list[dict[str, Any]]:
        """
        Return complete platform records.

        This method is useful for PostgreSQL-backed API responses that need
        both platform external IDs and names.
        """

        from app.storage.postgres.models import MitrePlatformModel

        statement = (
            select(MitrePlatformModel)
            .order_by(
                MitrePlatformModel.name.asc(),
            )
        )

        result = await self.session.execute(
            statement,
        )

        rows = result.scalars().all()

        return [
            {
                "id": row.external_id,
                "name": row.name,
                "description": row.description or "",
            }
            for row in rows
        ]

    async def count_platforms(self) -> int:
        """Return the total number of imported platforms."""

        from app.storage.postgres.models import MitrePlatformModel

        result = await self.session.execute(
            select(
                func.count(
                    MitrePlatformModel.id,
                ),
            ),
        )

        return int(
            result.scalar_one(),
        )

    # ========================================================================
    # Techniques
    # ========================================================================

    async def list_techniques(
        self,
        *,
        search: str | None = None,
        tactic: str | None = None,
        platform: str | None = None,
        technique_type: str | None = None,
        page: int = 1,
        page_size: int = 30,
    ) -> tuple[list[MitreTechnique], int]:
        """
        Return filtered and paginated top-level techniques.

        Search fields:
            - external_id
            - name
            - description

        Supported type filters:
            TECHNIQUE
            SUB_TECHNIQUE
        """

        from app.storage.postgres.models import (
            MitrePlatformModel,
            MitreTacticModel,
            MitreTechniqueModel,
        )

        statement = (
            select(MitreTechniqueModel)
            .options(
                selectinload(
                    MitreTechniqueModel.tactics,
                ),
                selectinload(
                    MitreTechniqueModel.platforms,
                ),
            )
        )

        count_statement = select(
            func.count(
                MitreTechniqueModel.id,
            ),
        )

        filters: list[Any] = []

        # --------------------------------------------------------------------
        # Search
        # --------------------------------------------------------------------

        normalized_search = (
            search.strip()
            if search
            else ""
        )

        if normalized_search:
            pattern = f"%{normalized_search}%"

            filters.append(
                or_(
                    MitreTechniqueModel.external_id.ilike(
                        pattern,
                    ),
                    MitreTechniqueModel.name.ilike(
                        pattern,
                    ),
                    MitreTechniqueModel.description.ilike(
                        pattern,
                    ),
                ),
            )

        # --------------------------------------------------------------------
        # Technique type
        # --------------------------------------------------------------------

        if technique_type:
            normalized_type = technique_type.strip().upper()

            if normalized_type not in {
                "TECHNIQUE",
                "SUB_TECHNIQUE",
            }:
                raise MitreRepositoryError(
                    "invalid MITRE technique type: "
                    f"{technique_type}",
                )

            filters.append(
                MitreTechniqueModel.type
                == normalized_type,
            )

        # --------------------------------------------------------------------
        # Tactic
        # --------------------------------------------------------------------

        if tactic:
            normalized_tactic = tactic.strip()

            if normalized_tactic:
                statement = statement.join(
                    MitreTechniqueModel.tactics,
                )

                count_statement = count_statement.join(
                    MitreTechniqueModel.tactics,
                )

                filters.append(
                    or_(
                        MitreTacticModel.external_id
                        == normalized_tactic,
                        MitreTacticModel.name.ilike(
                            f"%{normalized_tactic}%",
                        ),
                    ),
                )

        # --------------------------------------------------------------------
        # Platform
        # --------------------------------------------------------------------

        if platform:
            normalized_platform = platform.strip()

            if normalized_platform:
                statement = statement.join(
                    MitreTechniqueModel.platforms,
                )

                count_statement = count_statement.join(
                    MitreTechniqueModel.platforms,
                )

                filters.append(
                    or_(
                        MitrePlatformModel.external_id
                        == normalized_platform,
                        MitrePlatformModel.name.ilike(
                            f"%{normalized_platform}%",
                        ),
                    ),
                )

        # --------------------------------------------------------------------
        # Filters
        # --------------------------------------------------------------------

        if filters:
            statement = statement.where(
                *filters,
            )

            count_statement = count_statement.where(
                *filters,
            )

        # --------------------------------------------------------------------
        # Count
        # --------------------------------------------------------------------

        count_result = await self.session.execute(
            count_statement.distinct(),
        )

        total = int(
            count_result.scalar_one(),
        )

        # --------------------------------------------------------------------
        # Pagination
        # --------------------------------------------------------------------

        normalized_page = max(
            1,
            page,
        )

        normalized_page_size = min(
            30,
            max(
                1,
                page_size,
            ),
        )

        offset = (
            normalized_page - 1
        ) * normalized_page_size

        statement = (
            statement
            .distinct()
            .order_by(
                MitreTechniqueModel.external_id.asc(),
            )
            .offset(offset)
            .limit(normalized_page_size)
        )

        result = await self.session.execute(
            statement,
        )

        rows = result.scalars().unique().all()

        return (
            [
                self._technique_domain(row)
                for row in rows
            ],
            total,
        )

    async def get_technique(
        self,
        technique_id: str,
    ) -> MitreTechnique | None:
        """
        Return one top-level technique by MITRE external ID.

        Example:
            T1059
        """

        from app.storage.postgres.models import MitreTechniqueModel

        normalized_id = technique_id.strip()

        statement = (
            select(MitreTechniqueModel)
            .options(
                selectinload(
                    MitreTechniqueModel.tactics,
                ),
                selectinload(
                    MitreTechniqueModel.platforms,
                ),
            )
            .where(
                MitreTechniqueModel.external_id
                == normalized_id,
                MitreTechniqueModel.type
                == "TECHNIQUE",
            )
        )

        result = await self.session.execute(
            statement,
        )

        row = result.scalar_one_or_none()

        if row is None:
            return None

        return self._technique_domain(row)

    async def get_technique_any(
        self,
        technique_id: str,
    ) -> MitreTechnique | MitreSubTechnique | None:
        """
        Return either a top-level technique or a sub-technique by external ID.
        """

        from app.storage.postgres.models import MitreTechniqueModel

        normalized_id = technique_id.strip()

        statement = (
            select(MitreTechniqueModel)
            .options(
                selectinload(
                    MitreTechniqueModel.tactics,
                ),
                selectinload(
                    MitreTechniqueModel.platforms,
                ),
                selectinload(
                    MitreTechniqueModel.parent,
                ),
            )
            .where(
                MitreTechniqueModel.external_id
                == normalized_id,
            )
        )

        result = await self.session.execute(
            statement,
        )

        row = result.scalar_one_or_none()

        if row is None:
            return None

        if row.type == "SUB_TECHNIQUE":
            return self._subtechnique_domain(row)

        return self._technique_domain(row)

    async def get_technique_by_uuid(
        self,
        technique_uuid: UUID,
    ) -> MitreTechnique | None:
        """Return one top-level technique by database UUID."""

        from app.storage.postgres.models import MitreTechniqueModel

        statement = (
            select(MitreTechniqueModel)
            .options(
                selectinload(
                    MitreTechniqueModel.tactics,
                ),
                selectinload(
                    MitreTechniqueModel.platforms,
                ),
            )
            .where(
                MitreTechniqueModel.id
                == technique_uuid,
                MitreTechniqueModel.type
                == "TECHNIQUE",
            )
        )

        result = await self.session.execute(
            statement,
        )

        row = result.scalar_one_or_none()

        if row is None:
            return None

        return self._technique_domain(row)

    async def get_technique_model(
        self,
        technique_id: str,
    ) -> Any | None:
        """
        Return the raw SQLAlchemy technique model.

        This is intentionally an internal repository operation for importer
        and relationship workflows.
        """

        from app.storage.postgres.models import MitreTechniqueModel

        statement = (
            select(MitreTechniqueModel)
            .where(
                MitreTechniqueModel.external_id
                == technique_id.strip(),
            )
        )

        result = await self.session.execute(
            statement,
        )

        return result.scalar_one_or_none()

    async def count_techniques(
        self,
        *,
        top_level_only: bool = False,
    ) -> int:
        """Return the number of imported techniques."""

        from app.storage.postgres.models import MitreTechniqueModel

        statement = select(
            func.count(
                MitreTechniqueModel.id,
            ),
        )

        if top_level_only:
            statement = statement.where(
                MitreTechniqueModel.type
                == "TECHNIQUE",
            )

        result = await self.session.execute(
            statement,
        )

        return int(
            result.scalar_one(),
        )

    async def count_subtechniques(self) -> int:
        """Return the total number of imported sub-techniques."""

        from app.storage.postgres.models import MitreTechniqueModel

        result = await self.session.execute(
            select(
                func.count(
                    MitreTechniqueModel.id,
                ),
            ).where(
                MitreTechniqueModel.type
                == "SUB_TECHNIQUE",
            ),
        )

        return int(
            result.scalar_one(),
        )

    # ========================================================================
    # Sub-techniques
    # ========================================================================

    async def list_subtechniques(
        self,
        parent_id: str,
    ) -> list[MitreSubTechnique]:
        """
        Return all sub-techniques belonging to a parent technique.

        IMPORTANT:
            API/domain callers provide the MITRE external ID (e.g. T1059).
            PostgreSQL stores parent_id as UUID.

        The repository therefore resolves:
            T1059 → UUID → child.parent_id
        """

        from app.storage.postgres.models import MitreTechniqueModel

        normalized_parent_id = parent_id.strip()

        parent_statement = select(
            MitreTechniqueModel.id,
        ).where(
            MitreTechniqueModel.external_id
            == normalized_parent_id,
            MitreTechniqueModel.type
            == "TECHNIQUE",
        )

        parent_result = await self.session.execute(
            parent_statement,
        )

        parent_uuid = parent_result.scalar_one_or_none()

        if parent_uuid is None:
            return []

        statement = (
            select(MitreTechniqueModel)
            .options(
                selectinload(
                    MitreTechniqueModel.tactics,
                ),
                selectinload(
                    MitreTechniqueModel.platforms,
                ),
                selectinload(
                    MitreTechniqueModel.parent,
                ),
            )
            .where(
                MitreTechniqueModel.parent_id
                == parent_uuid,
                MitreTechniqueModel.type
                == "SUB_TECHNIQUE",
            )
            .order_by(
                MitreTechniqueModel.external_id.asc(),
            )
        )

        result = await self.session.execute(
            statement,
        )

        rows = result.scalars().all()

        return [
            self._subtechnique_domain(row)
            for row in rows
        ]

    async def get_subtechnique(
        self,
        subtechnique_id: str,
    ) -> MitreSubTechnique | None:
        """Return one sub-technique by MITRE external ID."""

        from app.storage.postgres.models import MitreTechniqueModel

        normalized_id = subtechnique_id.strip()

        statement = (
            select(MitreTechniqueModel)
            .options(
                selectinload(
                    MitreTechniqueModel.tactics,
                ),
                selectinload(
                    MitreTechniqueModel.platforms,
                ),
                selectinload(
                    MitreTechniqueModel.parent,
                ),
            )
            .where(
                MitreTechniqueModel.external_id
                == normalized_id,
                MitreTechniqueModel.type
                == "SUB_TECHNIQUE",
            )
        )

        result = await self.session.execute(
            statement,
        )

        row = result.scalar_one_or_none()

        if row is None:
            return None

        return self._subtechnique_domain(row)

    async def count_subtechniques_for_parent(
        self,
        parent_id: str,
    ) -> int:
        """
        Return sub-technique count for a parent technique external ID.
        """

        from app.storage.postgres.models import MitreTechniqueModel

        normalized_parent_id = parent_id.strip()

        parent_statement = select(
            MitreTechniqueModel.id,
        ).where(
            MitreTechniqueModel.external_id
            == normalized_parent_id,
            MitreTechniqueModel.type
            == "TECHNIQUE",
        )

        parent_result = await self.session.execute(
            parent_statement,
        )

        parent_uuid = parent_result.scalar_one_or_none()

        if parent_uuid is None:
            return 0

        result = await self.session.execute(
            select(
                func.count(
                    MitreTechniqueModel.id,
                ),
            ).where(
                MitreTechniqueModel.parent_id
                == parent_uuid,
                MitreTechniqueModel.type
                == "SUB_TECHNIQUE",
            ),
        )

        return int(
            result.scalar_one(),
        )

    # ========================================================================
    # References
    # ========================================================================

    async def list_references(
        self,
        technique_id: str,
    ) -> list[MitreReference]:
        """
        Return references associated with one MITRE technique.
        """

        from app.storage.postgres.models import (
            MitreReferenceModel,
            MitreTechniqueModel,
        )

        normalized_id = technique_id.strip()

        statement = (
            select(MitreReferenceModel)
            .join(
                MitreTechniqueModel.references,
            )
            .where(
                MitreTechniqueModel.external_id
                == normalized_id,
            )
            .order_by(
                MitreReferenceModel.id.asc(),
            )
        )

        result = await self.session.execute(
            statement,
        )

        rows = result.scalars().all()

        return [
            self._reference_domain(row)
            for row in rows
        ]

    # ========================================================================
    # Relationships
    # ========================================================================

    async def list_relationships(
        self,
        *,
        source_id: str | None = None,
        target_id: str | None = None,
        relationship_type: str | None = None,
    ) -> list[dict[str, Any]]:
        """
        Return raw imported STIX relationships.

        Source and target identifiers remain external MITRE/STIX identifiers.
        """

        from app.storage.postgres.models import (
            MitreRelationshipModel,
        )

        statement = select(
            MitreRelationshipModel,
        )

        if source_id:
            statement = statement.where(
                MitreRelationshipModel.source_external_id
                == source_id.strip(),
            )

        if target_id:
            statement = statement.where(
                MitreRelationshipModel.target_external_id
                == target_id.strip(),
            )

        if relationship_type:
            statement = statement.where(
                MitreRelationshipModel.relationship_type
                == relationship_type.strip(),
            )

        statement = statement.order_by(
            MitreRelationshipModel.id.asc(),
        )

        result = await self.session.execute(
            statement,
        )

        rows = result.scalars().all()

        return [
            self._relationship_dict(row)
            for row in rows
        ]

    # ========================================================================
    # Statistics
    # ========================================================================

    async def statistics(self) -> dict[str, int]:
        """
        Return base statistics for the imported ATT&CK knowledge.
        """

        tactics = await self.count_tactics()

        techniques = await self.count_techniques(
            top_level_only=True,
        )

        subtechniques = await self.count_subtechniques()

        platforms = await self.count_platforms()

        return {
            "tactics": tactics,
            "techniques": techniques,
            "subtechniques": subtechniques,
            "platforms": platforms,
        }

    # ========================================================================
    # Importer Support
    # ========================================================================
    #
    # These methods are persistence primitives.
    #
    # They are intentionally NOT exposed as FastAPI CRUD endpoints.
    #
    # The official ATT&CK importer is the authoritative writer.
    #
    # ========================================================================

    async def upsert_tactic(
        self,
        *,
        external_id: str,
        name: str,
        description: str = "",
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> Any:
        """
        Insert or update one MITRE tactic.

        Returns the SQLAlchemy model.
        """

        from app.storage.postgres.models import MitreTacticModel

        normalized_external_id = external_id.strip()
        normalized_name = name.strip()
        normalized_description = description.strip()

        statement = select(
            MitreTacticModel,
        ).where(
            MitreTacticModel.external_id
            == normalized_external_id,
        )

        result = await self.session.execute(
            statement,
        )

        row = result.scalar_one_or_none()

        if row is None:
            row = MitreTacticModel(
                external_id=normalized_external_id,
                name=normalized_name,
                description=normalized_description,
                created_at=(
                    created_at
                    if created_at is not None
                    else datetime.now(UTC)
                ),
                updated_at=(
                    updated_at
                    if updated_at is not None
                    else datetime.now(UTC)
                ),
            )

            self.session.add(row)

        else:
            row.name = normalized_name
            row.description = normalized_description
            row.updated_at = (
                updated_at
                if updated_at is not None
                else datetime.now(UTC)
            )

        await self.session.flush()

        return row

    async def upsert_technique(
        self,
        *,
        external_id: str,
        name: str,
        description: str = "",
        technique_type: str = "TECHNIQUE",
        parent_id: UUID | None = None,
        created_at: datetime | None = None,
        updated_at: datetime | None = None,
    ) -> Any:
        """
        Insert or update a MITRE technique or sub-technique.

        parent_id MUST be the PostgreSQL UUID of the parent technique.

        The importer should resolve parent external IDs to UUIDs before
        calling this method.
        """

        from app.storage.postgres.models import MitreTechniqueModel

        normalized_external_id = external_id.strip()
        normalized_name = name.strip()
        normalized_description = description.strip()
        normalized_type = technique_type.strip().upper()

        if normalized_type not in {
            "TECHNIQUE",
            "SUB_TECHNIQUE",
        }:
            raise MitreRepositoryError(
                f"invalid MITRE technique type: {technique_type}",
            )

        if normalized_type == "TECHNIQUE":
            parent_id = None

        statement = select(
            MitreTechniqueModel,
        ).where(
            MitreTechniqueModel.external_id
            == normalized_external_id,
        )

        result = await self.session.execute(
            statement,
        )

        row = result.scalar_one_or_none()

        now = datetime.now(UTC)

        if row is None:
            row = MitreTechniqueModel(
                external_id=normalized_external_id,
                name=normalized_name,
                description=normalized_description,
                type=normalized_type,
                parent_id=parent_id,
                created_at=(
                    created_at
                    if created_at is not None
                    else now
                ),
                updated_at=(
                    updated_at
                    if updated_at is not None
                    else now
                ),
            )

            self.session.add(row)

        else:
            row.name = normalized_name
            row.description = normalized_description
            row.type = normalized_type
            row.parent_id = parent_id
            row.updated_at = (
                updated_at
                if updated_at is not None
                else now
            )

        await self.session.flush()

        return row

    async def upsert_platform(
        self,
        *,
        name: str,
        external_id: str | None = None,
        description: str = "",
    ) -> Any:
        """
        Insert or update one MITRE platform.

        The database schema has a unique external_id. The importer should
        therefore provide a deterministic external_id for each platform.
        """

        from app.storage.postgres.models import MitrePlatformModel

        normalized_name = name.strip()

        if not normalized_name:
            raise MitreRepositoryError(
                "MITRE platform name cannot be empty",
            )

        normalized_external_id = (
            external_id.strip()
            if external_id
            else None
        )

        normalized_description = description.strip()

        if normalized_external_id:
            statement = select(
                MitrePlatformModel,
            ).where(
                MitrePlatformModel.external_id
                == normalized_external_id,
            )
        else:
            statement = select(
                MitrePlatformModel,
            ).where(
                MitrePlatformModel.name
                == normalized_name,
            )

        result = await self.session.execute(
            statement,
        )

        row = result.scalar_one_or_none()

        now = datetime.now(UTC)

        if row is None:
            if not normalized_external_id:
                raise MitreRepositoryError(
                    "platform external_id is required for new "
                    "MITRE platform records",
                )

            row = MitrePlatformModel(
                external_id=normalized_external_id,
                name=normalized_name,
                description=normalized_description,
                created_at=now,
                updated_at=now,
            )

            self.session.add(row)

        else:
            row.name = normalized_name
            row.description = normalized_description
            row.updated_at = now

        await self.session.flush()

        return row

    async def replace_technique_tactics(
        self,
        technique: Any,
        tactics: Sequence[Any],
    ) -> None:
        """
        Replace tactic relationships for one SQLAlchemy technique model.
        """

        technique.tactics = list(
            dict.fromkeys(tactics),
        )

        await self.session.flush()

    async def replace_technique_platforms(
        self,
        technique: Any,
        platforms: Sequence[Any],
    ) -> None:
        """
        Replace platform relationships for one SQLAlchemy technique model.
        """

        technique.platforms = list(
            dict.fromkeys(platforms),
        )

        await self.session.flush()

    async def replace_technique_references(
        self,
        technique: Any,
        references: Sequence[Any],
    ) -> None:
        """
        Replace external references for one SQLAlchemy technique model.
        """

        technique.references = list(
            dict.fromkeys(references),
        )

        await self.session.flush()

    async def upsert_reference(
        self,
        *,
        technique_id: UUID | None = None,
        source_name: str | None = None,
        url: str | None = None,
        external_id: str | None = None,
        description: str | None = None,
    ) -> Any:
        """
        Insert or update one MITRE external reference.

        A reference belongs to one technique in migration 008, therefore
        technique_id is supported here when the caller wants to persist the
        relationship directly.
        """

        from app.storage.postgres.models import MitreReferenceModel

        normalized_source = (
            source_name.strip()
            if source_name
            else ""
        )

        normalized_url = (
            url.strip()
            if url
            else None
        )

        normalized_external_id = (
            external_id.strip()
            if external_id
            else None
        )

        normalized_description = (
            description.strip()
            if description
            else ""
        )

        if not normalized_source:
            raise MitreRepositoryError(
                "MITRE reference source_name cannot be empty",
            )

        conditions: list[Any] = []

        if normalized_url:
            conditions.append(
                MitreReferenceModel.url
                == normalized_url,
            )

        if normalized_external_id:
            conditions.append(
                MitreReferenceModel.external_id
                == normalized_external_id,
            )

        if not conditions:
            conditions.append(
                MitreReferenceModel.source_name
                == normalized_source,
            )

        statement = select(
            MitreReferenceModel,
        ).where(
            or_(*conditions),
        )

        if technique_id is not None:
            statement = statement.where(
                MitreReferenceModel.technique_id
                == technique_id,
            )

        result = await self.session.execute(
            statement,
        )

        row = result.scalar_one_or_none()

        if row is None:
            if technique_id is None:
                raise MitreRepositoryError(
                    "technique_id is required when creating a "
                    "MITRE reference",
                )

            row = MitreReferenceModel(
                technique_id=technique_id,
                source_name=normalized_source,
                url=normalized_url,
                external_id=normalized_external_id,
                description=normalized_description,
            )

            self.session.add(row)

        else:
            row.source_name = normalized_source
            row.url = normalized_url
            row.external_id = normalized_external_id
            row.description = normalized_description

        await self.session.flush()

        return row

    async def upsert_relationship(
        self,
        *,
        relationship_external_id: str | None = None,
        source_external_id: str,
        target_external_id: str,
        relationship_type: str,
        description: str = "",
    ) -> Any:
        """
        Insert or update one imported MITRE STIX relationship.

        relationship_external_id is the authoritative STIX relationship ID.

        If omitted, the repository falls back to the source/target/type tuple.
        """

        from app.storage.postgres.models import (
            MitreRelationshipModel,
        )

        normalized_source = source_external_id.strip()
        normalized_target = target_external_id.strip()
        normalized_type = relationship_type.strip()
        normalized_description = description.strip()

        if not normalized_source:
            raise MitreRepositoryError(
                "MITRE relationship source cannot be empty",
            )

        if not normalized_target:
            raise MitreRepositoryError(
                "MITRE relationship target cannot be empty",
            )

        if not normalized_type:
            raise MitreRepositoryError(
                "MITRE relationship type cannot be empty",
            )

        normalized_relationship_id = (
            relationship_external_id.strip()
            if relationship_external_id
            else None
        )

        if normalized_relationship_id:
            statement = select(
                MitreRelationshipModel,
            ).where(
                MitreRelationshipModel.relationship_external_id
                == normalized_relationship_id,
            )
        else:
            statement = select(
                MitreRelationshipModel,
            ).where(
                MitreRelationshipModel.source_external_id
                == normalized_source,
                MitreRelationshipModel.target_external_id
                == normalized_target,
                MitreRelationshipModel.relationship_type
                == normalized_type,
            )

        result = await self.session.execute(
            statement,
        )

        row = result.scalar_one_or_none()

        now = datetime.now(UTC)

        if row is None:
            if not normalized_relationship_id:
                raise MitreRepositoryError(
                    "relationship_external_id is required when "
                    "creating a MITRE dataset relationship",
                )

            row = MitreRelationshipModel(
                relationship_external_id=normalized_relationship_id,
                source_external_id=normalized_source,
                target_external_id=normalized_target,
                relationship_type=normalized_type,
                description=normalized_description,
                created_at=now,
                updated_at=now,
            )

            self.session.add(row)

        else:
            if normalized_relationship_id:
                row.relationship_external_id = (
                    normalized_relationship_id
                )

            row.source_external_id = normalized_source
            row.target_external_id = normalized_target
            row.relationship_type = normalized_type
            row.description = normalized_description
            row.updated_at = now

        await self.session.flush()

        return row

    async def clear_relationships(self) -> None:
        """
        Delete all imported dataset relationships.
        """

        from app.storage.postgres.models import (
            MitreRelationshipModel,
        )

        await self.session.execute(
            delete(MitreRelationshipModel),
        )

        await self.session.flush()

    async def clear_knowledge(self) -> None:
        """
        Remove all MITRE ATT&CK knowledge.

        This is intended for a complete dataset replacement operation only.

        Detection → MITRE mappings are deliberately untouched.
        """

        from app.storage.postgres.models import (
            MitrePlatformModel,
            MitreReferenceModel,
            MitreRelationshipModel,
            MitreTacticModel,
            MitreTechniqueModel,
        )

        # --------------------------------------------------------------------
        # Relationships
        # --------------------------------------------------------------------

        await self.session.execute(
            delete(MitreRelationshipModel),
        )

        # --------------------------------------------------------------------
        # References
        # --------------------------------------------------------------------

        await self.session.execute(
            delete(MitreReferenceModel),
        )

        # --------------------------------------------------------------------
        # Techniques
        # --------------------------------------------------------------------

        await self.session.execute(
            delete(MitreTechniqueModel),
        )

        # --------------------------------------------------------------------
        # Tactics
        # --------------------------------------------------------------------

        await self.session.execute(
            delete(MitreTacticModel),
        )

        # --------------------------------------------------------------------
        # Platforms
        # --------------------------------------------------------------------

        await self.session.execute(
            delete(MitrePlatformModel),
        )

        await self.session.flush()

    # ========================================================================
    # Conversion Helpers
    # ========================================================================

    @staticmethod
    def _tactic_domain(
        row: Any,
    ) -> MitreTactic:
        """
        Convert SQLAlchemy tactic model to domain model.
        """

        return MitreTactic(
            id=row.external_id,
            external_id=row.external_id,
            name=row.name,
            description=row.description or "",
        )

    @staticmethod
    def _technique_domain(
        row: Any,
    ) -> MitreTechnique:
        """
        Convert SQLAlchemy top-level technique model to domain model.
        """

        tactic_ids = tuple(
            dict.fromkeys(
                tactic.external_id
                for tactic in (
                    getattr(
                        row,
                        "tactics",
                        None,
                    )
                    or []
                )
            ),
        )

        platform_objects = tuple(
            getattr(
                row,
                "platforms",
                None,
            )
            or []
        )

        platform_ids = tuple(
            dict.fromkeys(
                (
                    getattr(
                        platform,
                        "external_id",
                        None,
                    )
                    or getattr(
                        platform,
                        "name",
                        "",
                    )
                )
                for platform in platform_objects
            ),
        )

        platform_names = tuple(
            dict.fromkeys(
                (
                    getattr(
                        platform,
                        "name",
                        "",
                    )
                    or getattr(
                        platform,
                        "external_id",
                        "",
                    )
                )
                for platform in platform_objects
            ),
        )

        return MitreTechnique(
            id=row.external_id,
            external_id=row.external_id,
            name=row.name,
            description=row.description or "",
            tactic_ids=tactic_ids,
            platform_ids=tuple(
                value
                for value in platform_ids
                if value
            ),
            platforms=tuple(
                value
                for value in platform_names
                if value
            ),
        )

    @staticmethod
    def _subtechnique_domain(
        row: Any,
    ) -> MitreSubTechnique:
        """
        Convert SQLAlchemy sub-technique model to domain model.

        parent_id is converted from the database UUID to the parent
        technique's MITRE external ID.
        """

        tactic_ids = tuple(
            dict.fromkeys(
                tactic.external_id
                for tactic in (
                    getattr(
                        row,
                        "tactics",
                        None,
                    )
                    or []
                )
            ),
        )

        platform_objects = tuple(
            getattr(
                row,
                "platforms",
                None,
            )
            or []
        )

        platform_ids = tuple(
            dict.fromkeys(
                (
                    getattr(
                        platform,
                        "external_id",
                        None,
                    )
                    or getattr(
                        platform,
                        "name",
                        "",
                    )
                )
                for platform in platform_objects
            ),
        )

        platform_names = tuple(
            dict.fromkeys(
                (
                    getattr(
                        platform,
                        "name",
                        "",
                    )
                    or getattr(
                        platform,
                        "external_id",
                        "",
                    )
                )
                for platform in platform_objects
            ),
        )

        parent = getattr(
            row,
            "parent",
            None,
        )

        if parent is None:
            raise MitreRepositoryError(
                "MITRE sub-technique has no loaded parent: "
                f"{row.external_id}",
            )

        return MitreSubTechnique(
            id=row.external_id,
            external_id=row.external_id,
            name=row.name,
            parent_id=parent.external_id,
            description=row.description or "",
            tactic_ids=tactic_ids,
            platform_ids=tuple(
                value
                for value in platform_ids
                if value
            ),
            platforms=tuple(
                value
                for value in platform_names
                if value
            ),
        )

    @staticmethod
    def _reference_domain(
        row: Any,
    ) -> MitreReference:
        """
        Convert SQLAlchemy reference model to domain model.
        """

        return MitreReference(
            source_name=row.source_name,
            url=row.url,
            external_id=row.external_id,
            description=row.description or "",
        )

    @staticmethod
    def _reference_dict(
        row: Any,
    ) -> dict[str, Any]:
        """
        Convert a reference model to a transport-neutral dictionary.
        """

        return {
            "id": getattr(
                row,
                "id",
                None,
            ),
            "source_name": getattr(
                row,
                "source_name",
                None,
            ),
            "url": getattr(
                row,
                "url",
                None,
            ),
            "external_id": getattr(
                row,
                "external_id",
                None,
            ),
            "description": getattr(
                row,
                "description",
                "",
            )
            or "",
        }

    @staticmethod
    def _relationship_dict(
        row: Any,
    ) -> dict[str, Any]:
        """
        Convert a relationship model to a transport-neutral dictionary.
        """

        return {
            "id": getattr(
                row,
                "id",
                None,
            ),
            "relationship_external_id": getattr(
                row,
                "relationship_external_id",
                None,
            ),
            "source_external_id": getattr(
                row,
                "source_external_id",
                None,
            ),
            "target_external_id": getattr(
                row,
                "target_external_id",
                None,
            ),
            "relationship_type": getattr(
                row,
                "relationship_type",
                None,
            ),
            "description": getattr(
                row,
                "description",
                "",
            )
            or "",
        }


# ============================================================================
# Public API
# ============================================================================


__all__ = [
    "MitreNotFoundError",
    "MitreRepository",
    "MitreRepositoryError",
]