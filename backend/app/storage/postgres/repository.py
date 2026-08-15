from __future__ import annotations

from typing import Any

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.storage.postgres.models import StorageRecord


class PostgresStorageRepository:
    """Repository for structured records without exposing SQLAlchemy to services."""

    def __init__(self, session: AsyncSession) -> None:
        self.session = session

    async def upsert(
        self,
        *,
        entity_type: str,
        entity_id: str,
        payload: dict[str, Any],
    ) -> StorageRecord:
        entity_type = entity_type.strip()
        entity_id = entity_id.strip()
        if not entity_type or not entity_id:
            raise ValueError("entity_type and entity_id must not be empty")

        result = await self.session.execute(
            select(StorageRecord).where(
                StorageRecord.entity_type == entity_type,
                StorageRecord.entity_id == entity_id,
            )
        )
        record = result.scalar_one_or_none()

        if record is None:
            record = StorageRecord(
                entity_type=entity_type,
                entity_id=entity_id,
                payload=payload,
            )
            self.session.add(record)
        else:
            record.payload = payload

        await self.session.flush()
        return record

    async def get(
        self,
        *,
        entity_type: str,
        entity_id: str,
    ) -> StorageRecord | None:
        result = await self.session.execute(
            select(StorageRecord).where(
                StorageRecord.entity_type == entity_type,
                StorageRecord.entity_id == entity_id,
            )
        )
        return result.scalar_one_or_none()
