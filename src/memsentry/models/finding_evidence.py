from __future__ import annotations

from typing import Any
from uuid import UUID

from pydantic import BaseModel, Field


class FindingEvidenceCreate(BaseModel):
    """Data required to link provenance evidence to a finding."""

    finding_id: UUID
    plugin_run_id: UUID
    artifact_type: str | None = None
    source_reference: str | None = None
    supporting_data: dict[str, Any] = Field(default_factory=dict)
    explanation: str


class FindingEvidence(BaseModel):
    """Provenance evidence record linking a finding to plugin output."""

    id: UUID
    finding_id: UUID
    plugin_run_id: UUID
    artifact_type: str | None = None
    source_reference: str | None = None
    supporting_data: dict[str, Any]
    explanation: str
