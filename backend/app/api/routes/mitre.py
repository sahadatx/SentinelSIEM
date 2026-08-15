from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException

from app.api.dependencies import APIContainer, get_api_container
from app.api.schemas.mitre import MitreCoverageResponse, MitreTechniqueResponse

router = APIRouter(prefix="/mitre", tags=["mitre"])


@router.get("/coverage", response_model=MitreCoverageResponse)
def coverage(container: APIContainer = Depends(get_api_container)) -> MitreCoverageResponse:
    if container.mitre_service is None:
        raise HTTPException(status_code=503, detail="MITRE service is not configured")
    return MitreCoverageResponse.model_validate(container.mitre_service.coverage().model_dump())


@router.get("/techniques/{technique_id}", response_model=MitreTechniqueResponse)
def technique(technique_id: str, container: APIContainer = Depends(get_api_container)) -> MitreTechniqueResponse:
    if container.mitre_service is None:
        raise HTTPException(status_code=503, detail="MITRE service is not configured")
    result = container.mitre_service.technique(technique_id)
    if result is None:
        raise HTTPException(status_code=404, detail="MITRE technique not found")
    return MitreTechniqueResponse.model_validate(result.model_dump())
