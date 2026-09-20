"""SentinelSIEM MITRE ATT&CK API routes.

MITRE ATT&CK knowledge is exposed as a read-only security knowledge
module.

Architecture
------------

    enterprise-attack.json
             ↓
          Importer
             ↓
         PostgreSQL
             ↓
      MitreRepository
             ↓
       MitreService
             ↓
        MITRE API
             ↓
        MITRE Frontend

All MITRE knowledge endpoints require ``mitre:read``.

Detection → MITRE mapping management is intentionally NOT exposed as
MITRE knowledge CRUD from this router. Mapping creation/removal belongs
to the SentinelSIEM detection/mapping workflow.
"""

from __future__ import annotations

from typing import Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status

from app.api.dependencies import (
    APIContainer,
    get_api_container,
    get_mitre_service,
    require_permission,
)

from app.mitre.service import MitreService
from app.api.schemas.mitre import (
    MitreAnalyticsResponse,
    MitreCoverageResponse,
    MitreCoverageStateResponse,
    MitreKnowledgeResponse,
    MitreMatrixResponse,
    MitreMatrixTacticResponse,
    MitreMatrixTechniqueResponse,
    MitreMitigationResponse,
    MitrePaginationResponse,
    MitrePlatformListResponse,
    MitrePlatformResponse,
    MitreReferenceResponse,
    MitreStatisticsResponse,
    MitreSubTechniqueResponse,
    MitreTacticListResponse,
    MitreTacticResponse,
    MitreTechniqueDetailResponse,
    MitreTechniqueListResponse,
    MitreTechniqueRelationshipsResponse,
    MitreTechniqueResponse,
)
from app.auth.permissions import Permission


def _not_found(message: str) -> HTTPException:
    """Build a standard MITRE 404 response."""
    return HTTPException(
        status_code=status.HTTP_404_NOT_FOUND,
        detail=message,
    )


router = APIRouter(
    prefix="/mitre",
    tags=["mitre"],
)


# ============================================================================
# Dependencies
# ============================================================================


require_mitre_read = require_permission(
    Permission.MITRE_READ,
)


# ============================================================================
# Helpers
# ============================================================================


def _tactic_response(item) -> MitreTacticResponse:
    """Convert a MITRE tactic domain object into an API response."""
    return MitreTacticResponse(
        id=str(item.id),
        external_id=(
            str(item.external_id)
            if getattr(item, "external_id", None) is not None
            else None
        ),
        name=str(item.name),
        description=str(getattr(item, "description", "")),
    )


def _coverage_state_response(coverage) -> MitreCoverageStateResponse:
    """Convert a domain coverage object into the API response model."""
    return MitreCoverageStateResponse(
        technique_id=str(coverage.technique_id),
        state=getattr(coverage, "state", "UNMAPPED"),
        mapping_count=int(getattr(coverage, "mapping_count", 0)),
        detection_count=int(getattr(coverage, "detection_count", 0)),
        subtechnique_count=int(
            getattr(coverage, "subtechnique_count", 0)
        ),
        mapped_subtechnique_count=int(
            getattr(coverage, "mapped_subtechnique_count", 0)
        ),
        confidence=float(getattr(coverage, "confidence", 0.0)),
    )



def _technique_response(item) -> MitreTechniqueResponse:
    """Convert a MITRE technique domain object to an API response."""

    return MitreTechniqueResponse(
        id=str(item.id),
        external_id=(
            str(item.external_id)
            if getattr(item, "external_id", None) is not None
            else None
        ),
        name=str(item.name),
        type=str(getattr(item, "type", "TECHNIQUE")),
        tactic_ids=tuple(
            str(value)
            for value in getattr(item, "tactic_ids", ())
        ),
        platform_ids=tuple(
            str(value)
            for value in getattr(item, "platform_ids", ())
        ),
        platforms=tuple(
            str(value)
            for value in getattr(item, "platforms", ())
        ),
        description=str(
            getattr(item, "description", "")
        ),
    )


def _subtechnique_response(item) -> MitreSubTechniqueResponse:
    """Convert a MITRE sub-technique domain object into an API response."""
    return MitreSubTechniqueResponse(
        id=str(item.id),
        external_id=(
            str(item.external_id)
            if getattr(item, "external_id", None) is not None
            else None
        ),
        name=str(item.name),
        type=str(getattr(item, "type", "SUB_TECHNIQUE")),
        parent_id=str(item.parent_id),
        tactic_ids=tuple(
            str(value)
            for value in getattr(item, "tactic_ids", ())
        ),
        platform_ids=tuple(
            str(value)
            for value in getattr(item, "platform_ids", ())
        ),
        platforms=tuple(
            str(value)
            for value in getattr(item, "platforms", ())
        ),
        description=str(
            getattr(item, "description", "")
        ),
    )


@router.get(
    "",
    response_model=MitreKnowledgeResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def mitre(
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> MitreKnowledgeResponse:
    """Return the high-level MITRE ATT&CK knowledge summary."""



    tactics_result = await service.tactics()
    tactics = tuple(
        _tactic_response(tactic)
        for tactic in tactics_result
    )

    # Platforms are provided by the dataset-backed service when available.
    platforms_method = getattr(
        service,
        "platforms",
        None,
    )

    if callable(platforms_method):
        platforms_result = platforms_method()

        if hasattr(
            platforms_result,
            "__await__",
        ):
            platforms_result = await platforms_result

        platforms = tuple(
            MitrePlatformResponse(
                id=str(getattr(platform, "id", platform)),
                name=str(getattr(platform, "name", platform)),
            )
            for platform in platforms_result
        )
    else:
        platforms = ()

    statistics_result = await service.statistics()

    technique_count = int(statistics_result.get("techniques", 0))
    subtechnique_count = int(
        statistics_result.get("subtechniques", 0)
    )

    coverage_percent = float(
        statistics_result.get("coverage_percent", 0.0)
    )

    coverage_percent = 0.0

    try:
        analytics_result = await service.analytics()
        coverage_percent = float(
            analytics_result.coverage_percent,
        )
    except Exception:
        # The root knowledge endpoint must remain usable even when
        # coverage providers are temporarily unavailable.
        coverage_percent = 0.0

    statistics = MitreStatisticsResponse(
        tactics=len(tactics),
        techniques=technique_count,
        subtechniques=subtechnique_count,
        coverage_percent=coverage_percent,
    )

    return MitreKnowledgeResponse(
        tactics=tactics,
        platforms=platforms,
        statistics=statistics,
    )


# ============================================================================
# Statistics
# ============================================================================


@router.get(
    "/statistics",
    response_model=MitreStatisticsResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def statistics(
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> MitreStatisticsResponse:
    """Return statistics for the MITRE ATT&CK workspace."""

    tactics_count = await service.tactic_count()

    total_techniques = await service.technique_count(
        top_level_only=False,
    )

    top_level_techniques = await service.technique_count(
        top_level_only=True,
    )

    subtechnique_count = (
        total_techniques - top_level_techniques
    )

    coverage_percent = 0.0

    try:
        analytics_result = await service.analytics()
        coverage_percent = float(
            analytics_result.coverage_percent,
        )
    except Exception:
        pass

    return MitreStatisticsResponse(
        tactics=tactics_count,
        techniques=top_level_techniques,
        subtechniques=subtechnique_count,
        coverage_percent=coverage_percent,
    )


# ============================================================================

def _paginate(
    items: tuple,
    *,
    page: int,
    page_size: int,
) -> tuple[tuple, MitrePaginationResponse]:
    """Paginate an in-memory MITRE collection."""

    total = len(items)

    total_pages = (
        (total + page_size - 1) // page_size
        if total > 0
        else 0
    )

    start = (page - 1) * page_size
    end = start + page_size

    selected = items[start:end]

    pagination = MitrePaginationResponse(
        page=page,
        page_size=page_size,
        total=total,
        total_pages=total_pages,
    )

    return selected, pagination


# Tactics
# ============================================================================


@router.get(
    "/tactics",
    response_model=MitreTacticListResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def tactics(
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=30,
        ge=1,
        le=30,
    ),
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> MitreTacticListResponse:
    """Return MITRE ATT&CK tactics."""



    all_tactics = tuple(
        await service.tactics(),
    )

    selected, pagination = _paginate(
        all_tactics,
        page=page,
        page_size=page_size,
    )

    return MitreTacticListResponse(
        items=tuple(
            _tactic_response(tactic)
            for tactic in selected
        ),
        pagination=pagination,
    )


# ============================================================================
# Platforms
# ============================================================================


@router.get(
    "/platforms",
    response_model=MitrePlatformListResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def platforms(
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=30,
        ge=1,
        le=30,
    ),
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> MitrePlatformListResponse:
    """Return MITRE ATT&CK platforms."""



    method = getattr(
        service,
        "platforms",
        None,
    )

    if not callable(method):
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="MITRE platform provider is not configured",
        )

    result = method()

    if hasattr(
        result,
        "__await__",
    ):
        result = await result

    all_platforms = tuple(
        result,
    )

    selected, pagination = _paginate(
        all_platforms,
        page=page,
        page_size=page_size,
    )

    return MitrePlatformListResponse(
        items=tuple(
            MitrePlatformResponse(
                id=str(
                    getattr(platform, "id", platform),
                ),
                name=str(
                    getattr(platform, "name", platform),
                ),
            )
            for platform in selected
        ),
        pagination=pagination,
    )


# ============================================================================
# Techniques
# ============================================================================


@router.get(
    "/techniques",
    response_model=MitreTechniqueListResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def techniques(
    search: str | None = Query(
        default=None,
        max_length=200,
    ),
    tactic: str | None = Query(
        default=None,
        max_length=64,
    ),
    platform: str | None = Query(
        default=None,
        max_length=128,
    ),
    type: str | None = Query(
        default=None,
        alias="type",
        max_length=32,
    ),
    coverage: str | None = Query(
        default=None,
        max_length=32,
    ),
    page: int = Query(
        default=1,
        ge=1,
    ),
    page_size: int = Query(
        default=30,
        ge=1,
        le=30,
    ),
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> MitreTechniqueListResponse:
    """Return filtered MITRE ATT&CK techniques.

    Search targets:

    - technique ID;
    - technique name;
    - description.

    Filters are applied immediately by the frontend and can be combined.
    """



    # PostgreSQL is the authoritative source for normal
    # MITRE knowledge filtering and pagination.
    techniques_result, techniques_total = await service.techniques(
        search=search,
        tactic=tactic,
        platform=platform,
        technique_type=type,
        page=page,
        page_size=page_size,
    )

    # Coverage remains a separate Detection -> MITRE mapping
    # concern and is therefore applied after the knowledge query.
    filtered: list[Any] = []

    normalized_coverage = (
        coverage.strip().upper()
        if coverage
        else None
    )

    for technique in techniques_result:
        technique_id = str(
            getattr(
                technique,
                "id",
                "",
            ),
        )

        if normalized_coverage:
            try:
                coverage_state = (
                    await service.technique_coverage(
                        technique_id,
                    )
                )

                state = str(
                    coverage_state.state.value
                    if hasattr(
                        coverage_state.state,
                        "value",
                    )
                    else coverage_state.state,
                ).upper()

                if normalized_coverage == "COVERED":
                    expected = {
                        "FULL",
                        "COVERED",
                    }
                elif normalized_coverage in {
                    "PARTIAL",
                    "PARTIALLY_COVERED",
                }:
                    expected = {
                        "PARTIAL",
                        "PARTIALLY_COVERED",
                    }
                elif normalized_coverage in {
                    "NOT_COVERED",
                    "UNMAPPED",
                }:
                    expected = {
                        "UNMAPPED",
                        "NOT_COVERED",
                    }
                else:
                    expected = {
                        normalized_coverage,
                    }

                if state not in expected:
                    continue

            except KeyError:
                continue

        filtered.append(technique)

    items = tuple(
        _technique_response(technique)
        for technique in filtered
    )

    total_pages = (
        (techniques_total + page_size - 1) // page_size
        if techniques_total > 0
        else 0
    )

    pagination = MitrePaginationResponse(
        page=page,
        page_size=page_size,
        total=techniques_total,
        total_pages=total_pages,
    )

    return MitreTechniqueListResponse(
        items=tuple(
            _technique_response(
                technique,
            )
            for technique in filtered
        ),
        pagination=pagination,
    )


# ============================================================================
# Single Technique
# ============================================================================


@router.get(
    "/techniques/{technique_id}",
    response_model=MitreTechniqueResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def technique(
    technique_id: str,
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> MitreTechniqueResponse:
    """Return one MITRE ATT&CK technique."""



    try:
        result = await service.technique(
            technique_id,
        )
    except KeyError as exc:
        raise _not_found(
            "MITRE technique not found",
        ) from exc

    return _technique_response(
        result,
    )


# ============================================================================
# Sub-Techniques
# ============================================================================


@router.get(
    "/techniques/{technique_id}/sub-techniques",
    response_model=tuple[MitreSubTechniqueResponse, ...],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def subtechniques(
    technique_id: str,
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> tuple[MitreSubTechniqueResponse, ...]:
    """Return sub-techniques belonging to one parent technique."""



    try:
        result = await service.subtechniques_for_parent(
            technique_id,
        )
    except KeyError as exc:
        raise _not_found(
            "MITRE technique not found",
        ) from exc

    return tuple(
        _subtechnique_response(
            item,
        )
        for item in result
    )


# ============================================================================
# Technique Detail
# ============================================================================


@router.get(
    "/techniques/{technique_id}/detail",
    response_model=MitreTechniqueDetailResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def technique_detail(
    technique_id: str,
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> MitreTechniqueDetailResponse:
    """Return complete detail for one MITRE technique."""



    try:
        result = await service.technique_detail(
            technique_id,
        )
    except KeyError as exc:
        raise _not_found(
            "MITRE technique not found",
        ) from exc

    technique_response = _technique_response(
        result.technique,
    )

    references = tuple(
        MitreReferenceResponse.model_validate(
            item.model_dump()
            if hasattr(item, "model_dump")
            else item,
        )
        for item in getattr(
            result,
            "references",
            (),
        )
    )

    mitigations = tuple(
        MitreMitigationResponse.model_validate(
            item.model_dump()
            if hasattr(item, "model_dump")
            else item,
        )
        for item in getattr(
            result,
            "mitigations",
            (),
        )
    )

    return MitreTechniqueDetailResponse(
        technique=technique_response,
        coverage=_coverage_state_response(
            result.coverage,
        ),
        subtechniques=tuple(
            _subtechnique_response(
                item,
            )
            for item in result.subtechniques
        ),
        references=references,
        mitigations=mitigations,
        detection_guidance=str(
            getattr(
                result,
                "detection_guidance",
                "",
            ),
        ),
        mappings=(),
        detection_ids=result.detection_ids,
        event_ids=result.event_ids,
        alert_ids=result.alert_ids,
        incident_ids=result.incident_ids,
        ioc_ids=result.ioc_ids,
        asset_ids=result.asset_ids,
    )


# ============================================================================
# Technique Relationships
# ============================================================================


@router.get(
    "/techniques/{technique_id}/relationships",
    response_model=MitreTechniqueRelationshipsResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def technique_relationships(
    technique_id: str,
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> MitreTechniqueRelationshipsResponse:
    """Return SOC relationships for one MITRE technique."""



    try:
        result = await service.relationships_for_technique(
            technique_id,
        )
    except KeyError as exc:
        raise _not_found(
            "MITRE technique not found",
        ) from exc

    return MitreTechniqueRelationshipsResponse.model_validate(
        result,
    )


# ============================================================================
# Technique-specific Intelligence
# ============================================================================


async def _relationship_ids(
    service: Any,
    technique_id: str,
    field_name: str,
) -> tuple[Any, ...]:
    """Return relationship IDs from the service relationship contract."""

    result = await service.relationships_for_technique(
        technique_id,
    )

    return tuple(
        result.get(
            field_name,
            (),
        ),
    )


@router.get(
    "/techniques/{technique_id}/detections",
    response_model=tuple[str, ...],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def technique_detections(
    technique_id: str,
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> tuple[str, ...]:
    """Return SentinelSIEM detection IDs mapped to a technique."""



    try:
        return await _relationship_ids(
            service,
            technique_id,
            "detection_ids",
        )
    except KeyError as exc:
        raise _not_found(
            "MITRE technique not found",
        ) from exc


@router.get(
    "/techniques/{technique_id}/events",
    response_model=tuple[UUID, ...],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def technique_events(
    technique_id: str,
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> tuple[UUID, ...]:
    """Return security-event IDs associated with a technique."""



    try:
        return await _relationship_ids(
            service,
            technique_id,
            "event_ids",
        )
    except KeyError as exc:
        raise _not_found(
            "MITRE technique not found",
        ) from exc


@router.get(
    "/techniques/{technique_id}/alerts",
    response_model=tuple[UUID, ...],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def technique_alerts(
    technique_id: str,
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> tuple[UUID, ...]:
    """Return alert IDs associated with a technique."""



    try:
        return await _relationship_ids(
            service,
            technique_id,
            "alert_ids",
        )
    except KeyError as exc:
        raise _not_found(
            "MITRE technique not found",
        ) from exc


@router.get(
    "/techniques/{technique_id}/incidents",
    response_model=tuple[UUID, ...],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def technique_incidents(
    technique_id: str,
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> tuple[UUID, ...]:
    """Return incident IDs associated with a technique."""



    try:
        return await _relationship_ids(
            service,
            technique_id,
            "incident_ids",
        )
    except KeyError as exc:
        raise _not_found(
            "MITRE technique not found",
        ) from exc


@router.get(
    "/techniques/{technique_id}/iocs",
    response_model=tuple[str, ...],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def technique_iocs(
    technique_id: str,
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> tuple[str, ...]:
    """Return IOC identifiers associated with a technique."""



    try:
        return await _relationship_ids(
            service,
            technique_id,
            "ioc_ids",
        )
    except KeyError as exc:
        raise _not_found(
            "MITRE technique not found",
        ) from exc


# ============================================================================
# Coverage
# ============================================================================


@router.get(
    "/coverage",
    response_model=MitreCoverageResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def coverage(
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> MitreCoverageResponse:
    """Return aggregate MITRE ATT&CK detection coverage."""



    result = await service.coverage()

    return MitreCoverageResponse.model_validate(
        result.model_dump(),
    )


@router.get(
    "/coverage/tactics",
    response_model=dict[str, float],
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def tactic_coverage(
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> dict[str, float]:
    """Return coverage percentage grouped by ATT&CK tactic."""



    result = await service.analytics()

    return {
        str(tactic_id): float(value)
        for tactic_id, value in result.by_tactic.items()
    }


# ============================================================================
# Analytics
# ============================================================================


@router.get(
    "/analytics",
    response_model=MitreAnalyticsResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def analytics(
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> MitreAnalyticsResponse:
    """Return MITRE ATT&CK coverage analytics."""



    result = await service.analytics()

    return MitreAnalyticsResponse.model_validate(
        result.model_dump(),
    )


# ============================================================================
# Matrix
# ============================================================================


@router.get(
    "/matrix",
    response_model=MitreMatrixResponse,
    status_code=status.HTTP_200_OK,
    dependencies=[Depends(require_mitre_read)],
)
async def matrix(
    container: APIContainer = Depends(get_api_container),
    service: MitreService = Depends(get_mitre_service),
) -> MitreMatrixResponse:
    """Return the Enterprise ATT&CK matrix with coverage."""



    rows = await service.matrix()
    analytics_result = await service.analytics()
    tactics_result = await service.tactics()

    technique_by_id: dict[
        str,
        MitreMatrixTechniqueResponse,
    ] = {}

    for row in rows:
        technique = row["technique"]
        coverage_result = row["coverage"]
        subtechniques = row["subtechniques"]
        mappings = row["mappings"]

        mapping_ids = tuple(
            mapping.mapping_id
            for mapping in mappings
        )

        detection_ids = tuple(
            sorted(
                {
                    str(mapping.detection_id)
                    for mapping in mappings
                },
            ),
        )

        technique_by_id[
            technique.id
        ] = MitreMatrixTechniqueResponse(
            id=technique.id,
            external_id=getattr(
                technique,
                "external_id",
                None,
            ),
            name=technique.name,
            type=getattr(
                technique,
                "type",
                "TECHNIQUE",
            ),
            tactic_ids=tuple(
                technique.tactic_ids,
            ),
            platform_ids=tuple(
                getattr(
                    technique,
                    "platform_ids",
                    (),
                ),
            ),
            platforms=tuple(
                getattr(
                    technique,
                    "platforms",
                    (),
                ),
            ),
            description=technique.description,
            coverage=_coverage_state_response(
                coverage_result,
            ),
            subtechniques=tuple(
                _subtechnique_response(
                    item,
                )
                for item in subtechniques
            ),
            mapping_ids=mapping_ids,
            detection_ids=detection_ids,
        )

    tactic_responses: list[
        MitreMatrixTacticResponse
    ] = []

    for tactic in tactics_result:
        tactic_techniques = tuple(
            technique
            for technique in technique_by_id.values()
            if tactic.id in technique.tactic_ids
        )

        tactic_responses.append(
            MitreMatrixTacticResponse(
                id=tactic.id,
                external_id=getattr(
                    tactic,
                    "external_id",
                    None,
                ),
                name=tactic.name,
                description=tactic.description,
                techniques=tactic_techniques,
                coverage_percent=float(
                    analytics_result.by_tactic.get(
                        tactic.id,
                        0.0,
                    ),
                ),
            ),
        )

    return MitreMatrixResponse(
        tactics=tuple(
            tactic_responses,
        ),
        total_techniques=analytics_result.total_techniques,
        full_techniques=analytics_result.full_techniques,
        partial_techniques=analytics_result.partial_techniques,
        unmapped_techniques=analytics_result.unmapped_techniques,
        coverage_percent=analytics_result.coverage_percent,
    )


# ============================================================================
# Exports
# ============================================================================


__all__ = [
    "analytics",
    "coverage",
    "matrix",
    "mitre",
    "platforms",
    "router",
    "statistics",
    "subtechniques",
    "tactic_coverage",
    "tactics",
    "technique",
    "technique_alerts",
    "technique_detail",
    "technique_detections",
    "technique_events",
    "technique_incidents",
    "technique_iocs",
    "technique_relationships",
    "techniques",
]