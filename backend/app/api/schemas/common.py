from __future__ import annotations

from typing import Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

T = TypeVar("T")


class APIModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)


class ErrorBody(APIModel):
    code: str
    message: str
    request_id: str | None = None


class ErrorResponse(APIModel):
    error: ErrorBody


class Pagination(BaseModel):
    model_config = ConfigDict(extra="forbid")
    page: int = Field(ge=1)
    page_size: int = Field(ge=1, le=1000)
    total: int = Field(ge=0)


class PageResponse(BaseModel, Generic[T]):
    model_config = ConfigDict(extra="forbid")
    items: list[T]
    pagination: Pagination


class HealthResponse(APIModel):
    status: str
    service: str
    version: str


class SystemResponse(APIModel):
    service: str
    version: str
    environment: str
    capabilities: list[str]


class MessageResponse(APIModel):
    message: str


class IDResponse(APIModel):
    id: UUID
