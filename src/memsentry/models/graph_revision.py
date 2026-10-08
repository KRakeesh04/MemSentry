"""Investigator metadata; captured artifacts remain in their original tables."""

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field


class HypothesisNode(BaseModel):
    model_config = ConfigDict(extra="forbid")
    label: str = Field(min_length=1, max_length=200)
    category: str = Field(min_length=1, max_length=40)
    notes: str = Field(min_length=1, max_length=10000)


class ManualRelationship(BaseModel):
    model_config = ConfigDict(extra="forbid")
    source: str
    target: str
    label: str = Field(min_length=1, max_length=100)
    rationale: str = Field(min_length=1, max_length=10000)


class GraphDraft(BaseModel):
    model_config = ConfigDict(extra="forbid", allow_inf_nan=False)
    version: int = Field(default=1, ge=1, le=1)
    nodes: dict[str, HypothesisNode] = Field(default_factory=dict)
    edges: list[ManualRelationship] = Field(default_factory=list)
    notes: dict[str, str] = Field(default_factory=dict)
    visible: set[str] = Field(default_factory=set)
    hidden_edges: set[str] = Field(default_factory=set)
    positions: dict[str, tuple[float, float]] = Field(default_factory=dict)


class GraphRevision(BaseModel):
    id: UUID
    analysis_run_id: UUID
    name: str
    investigator: str
    created_at: datetime
    draft: GraphDraft
