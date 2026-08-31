from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class PluginRunStatus(StrEnum):
    """Execution status of a Volatility plugin run."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PluginRunCreate(BaseModel):
    """Data required to initiate a plugin execution record."""

    analysis_run_id: UUID
    plugin_name: str
    configuration: dict[str, Any] = Field(default_factory=dict)


class PluginRun(BaseModel):
    """A plugin run record stored in the MemSentry database."""

    id: UUID
    analysis_run_id: UUID
    plugin_name: str
    status: PluginRunStatus
    configuration: dict[str, Any]
    raw_output_path: Path | None = None
    raw_output_sha256: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    error_message: str | None = None
