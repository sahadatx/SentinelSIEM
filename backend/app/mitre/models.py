"""Strict MITRE ATT&CK domain contracts."""
from __future__ import annotations
from datetime import datetime, timezone
import re
from pydantic import BaseModel, ConfigDict, Field, field_validator

_TACTIC = re.compile(r"^TA\d{4}$")
_TECHNIQUE = re.compile(r"^T\d{4}$")
_SUBTECHNIQUE = re.compile(r"^T\d{4}\.\d{3}$")

def utc_now() -> datetime:
    return datetime.now(timezone.utc)

class MitreTactic(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    name: str
    description: str = ""
    @field_validator("id")
    @classmethod
    def valid_id(cls, v: str) -> str:
        if not _TACTIC.fullmatch(v):
            raise ValueError("invalid MITRE tactic ID")
        return v
    @field_validator("name")
    @classmethod
    def nonempty(cls, v: str) -> str:
        v = v.strip()
        if not v: raise ValueError("name cannot be empty")
        return v

class MitreTechnique(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    name: str
    tactic_ids: tuple[str, ...] = ()
    description: str = ""
    @field_validator("id")
    @classmethod
    def valid_id(cls, v: str) -> str:
        if not _TECHNIQUE.fullmatch(v): raise ValueError("invalid MITRE technique ID")
        return v
    @field_validator("tactic_ids")
    @classmethod
    def valid_tactics(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _TACTIC.fullmatch(x) for x in v):
            raise ValueError("invalid MITRE tactic ID")
        return tuple(dict.fromkeys(v))

class MitreSubTechnique(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str
    name: str
    parent_id: str
    tactic_ids: tuple[str, ...] = ()
    description: str = ""
    @field_validator("id")
    @classmethod
    def valid_id(cls, v: str) -> str:
        if not _SUBTECHNIQUE.fullmatch(v): raise ValueError("invalid MITRE sub-technique ID")
        return v
    @field_validator("parent_id")
    @classmethod
    def valid_parent(cls, v: str) -> str:
        if not _TECHNIQUE.fullmatch(v): raise ValueError("invalid parent technique ID")
        return v
    @field_validator("tactic_ids")
    @classmethod
    def valid_tactics(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _TACTIC.fullmatch(x) for x in v):
            raise ValueError("invalid MITRE tactic ID")
        return tuple(dict.fromkeys(v))

class DetectionMapping(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    detection_id: str = Field(min_length=1, max_length=200)
    technique_id: str
    subtechnique_id: str | None = None
    tactic_ids: tuple[str, ...] = ()
    confidence: float = Field(default=1.0, ge=0.0, le=1.0)
    source: str = Field(default="sentinelsiem", min_length=1, max_length=200)
    description: str = ""
    created_at: datetime = Field(default_factory=utc_now)
    @field_validator("technique_id")
    @classmethod
    def valid_technique(cls, v: str) -> str:
        if not _TECHNIQUE.fullmatch(v): raise ValueError("invalid MITRE technique ID")
        return v
    @field_validator("subtechnique_id")
    @classmethod
    def valid_subtechnique(cls, v: str | None) -> str | None:
        if v is not None and not _SUBTECHNIQUE.fullmatch(v):
            raise ValueError("invalid MITRE sub-technique ID")
        return v
    @field_validator("tactic_ids")
    @classmethod
    def valid_tactics(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if any(not _TACTIC.fullmatch(x) for x in v):
            raise ValueError("invalid MITRE tactic ID")
        return tuple(dict.fromkeys(v))

class NavigatorTechnique(BaseModel):
    model_config = ConfigDict(extra="forbid")
    techniqueID: str
    enabled: bool = True
    score: float = Field(default=1.0, ge=0.0, le=1.0)

class NavigatorLayer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = "4.5"
    name: str = "SentinelSIEM MITRE Coverage"
    domain: str = "enterprise-attack"
    description: str = ""
    techniques: list[NavigatorTechnique] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=utc_now)

class CoverageResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    total_techniques: int = Field(ge=0)
    mapped_techniques: int = Field(ge=0)
    coverage_percent: float = Field(ge=0.0, le=100.0)
    mapped_technique_ids: tuple[str, ...] = ()
    unmapped_technique_ids: tuple[str, ...] = ()
