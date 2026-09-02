from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID

from pydantic import BaseModel


class AnalysisRunStatus(StrEnum):
    """Lifecycle status of an analysis run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    COMPLETED_WITH_ERRORS = "completed_with_errors"
    FAILED = "failed"
    CANCELLED = "cancelled"


class HostOS(StrEnum):
    """Operating system hosting the MemSentry application."""

    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"


class AnalysisRunCreate(BaseModel):
    """Data required to create a new analysis run."""

    evidence_id: UUID
    application_version: str
    volatility_version: str
    host_os: HostOS


class AnalysisRun(BaseModel):
    """An analysis run stored in the MemSentry database."""

    id: UUID
    evidence_id: UUID
    status: AnalysisRunStatus
    application_version: str
    volatility_version: str
    host_os: HostOS
    created_at: datetime
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
