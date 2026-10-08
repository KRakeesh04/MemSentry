from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from memsentry.models.artifact import Artifact
from memsentry.models.case import Case
from memsentry.models.evidence import Evidence
from memsentry.models.finding import Finding
from memsentry.models.plugin_run import PluginRun


class ReportOptions(BaseModel):
    """Options for what to include in the generated report."""

    include_plugin_runs: bool = False
    include_artifacts: bool = False
    include_workflow_history: bool = False


class ReportData(BaseModel):
    """Aggregated forensic data for a report."""

    generated_at: datetime
    case: Case
    evidences: list[Evidence] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)

    plugin_runs: list[PluginRun] | None = None
    artifacts: list[Artifact] | None = None
    workflow_events: list[dict[str, Any]] | None = None
