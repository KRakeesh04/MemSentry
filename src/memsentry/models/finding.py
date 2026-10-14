from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Any
from uuid import UUID, uuid4

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
    finding_id: UUID = Field(default_factory=uuid4)
    rule_id: str
    title: str
    description: str
    severity: FindingSeverity
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    correlation_details: dict[str, Any] = Field(default_factory=dict)


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
