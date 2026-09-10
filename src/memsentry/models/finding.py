from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field


class FindingSeverity(StrEnum):
    """Severity classification for a detection rule finding."""

    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class FindingCreate(BaseModel):
    """Data required to record a detection finding."""

    analysis_run_id: UUID
    rule_id: str
    title: str
    description: str
    severity: FindingSeverity
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)


class Finding(BaseModel):
    """A finding stored in the MemSentry database."""

    id: UUID
    analysis_run_id: UUID
    rule_id: str
    title: str
    description: str
    severity: FindingSeverity
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    created_at: datetime
