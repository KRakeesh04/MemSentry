"""Persisted normalized Volatility artifact models."""

from __future__ import annotations

from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class ArtifactCreate(BaseModel):
    analysis_run_id: UUID
    plugin_run_id: UUID
    artifact_type: str = Field(min_length=1)
    pid: int | None = Field(default=None, ge=0)
    original_data: dict[str, Any]
    provenance: dict[str, Any]


class Artifact(BaseModel):
    id: UUID
    analysis_run_id: UUID
    plugin_run_id: UUID
    artifact_type: str
    pid: int | None = None
    original_data: dict[str, Any]
    provenance: dict[str, Any]
    created_at: datetime
