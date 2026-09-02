from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel, Field, field_validator


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

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, value: float | None) -> float | None:
        """Validate confidence score range when specified."""
        if value is not None and not (0.0 <= value <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0 inclusive")
        return value


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

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, value: float | None) -> float | None:
        """Validate confidence score range when specified."""
        if value is not None and not (0.0 <= value <= 1.0):
            raise ValueError("confidence must be between 0.0 and 1.0 inclusive")
        return value
