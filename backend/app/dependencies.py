from __future__ import annotations

from typing import Annotated

from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.dependencies import get_db_session
from app.assets.repository import AssetRepository
from app.assets.service import AssetService


# ============================================================================
# Database Session
# ============================================================================

DatabaseSession = Annotated[
    AsyncSession,
    Depends(get_db_session),
]


# ============================================================================
# Asset Repository
# ============================================================================


def get_asset_repository(
    db: DatabaseSession,
) -> AssetRepository:
    """
    Provide an AssetRepository backed by the application's
    existing asynchronous database session.
    """
    return AssetRepository(db)


# ============================================================================
# Asset Service
# ============================================================================


def get_asset_service(
    repository: Annotated[
        AssetRepository,
        Depends(get_asset_repository),
    ],
) -> AssetService:
    """
    Provide an AssetService backed by AssetRepository.
    """
    return AssetService(
        repository=repository,
    )


# ============================================================================
# Public Exports
# ============================================================================

__all__ = [
    "DatabaseSession",
    "get_asset_repository",
    "get_asset_service",
]