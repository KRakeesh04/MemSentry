from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel


class CaseStatus(StrEnum):
    """Possible lifecycle states for a case."""

    OPEN = "open"
    CLOSED = "closed"
    ARCHIVED = "archived"


class CaseCreate(BaseModel):
    """Data required when creating a new case."""

    case_number: str
    name: str
    description: str | None = None


class CaseUpdate(BaseModel):
    """Data allowed when updating an existing case."""

    name: str
    description: str | None = None


class Case(BaseModel):
    """A case stored in the MemSentry database."""

    id: UUID
    case_number: str
    name: str
    description: str | None
    status: CaseStatus
    created_at: datetime
    updated_at: datetime
