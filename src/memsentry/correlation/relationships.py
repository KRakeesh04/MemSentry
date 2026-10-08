"""Deterministic relationships supported by captured artifact fields."""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from memsentry.models.artifact import Artifact


@dataclass(frozen=True, slots=True)
class ArtifactRelationship:
    source_artifact_id: UUID
    target_artifact_id: UUID
    relationship_type: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)


def artifact_fields(artifact: Artifact) -> dict[str, Any]:
    return {**artifact.original_data, **artifact.original_data.get("normalized", {})}


def observed_relationships(artifacts: list[Artifact]) -> list[ArtifactRelationship]:
    """Join within a run; omit ambiguous/reused PIDs instead of guessing identity."""
    processes: dict[tuple[UUID, int], list[Artifact]] = defaultdict(list)
    for artifact in artifacts:
        if artifact.artifact_type in ("process", "process_tree") and artifact.pid is not None:
            processes[artifact.analysis_run_id, artifact.pid].append(artifact)
    owners = {}
    for key, records in processes.items():
        names = {artifact_fields(a).get("process_name") for a in records
                 if artifact_fields(a).get("process_name") is not None}
        times = {artifact_fields(a).get("created_at") for a in records
                 if artifact_fields(a).get("created_at") is not None}
        primary = [a for a in records if a.artifact_type == "process"]
        if len(primary) <= 1 and len(names) <= 1 and len(times) <= 1:
            owners[key] = min(primary or records, key=lambda a: str(a.id))
    links = []
    ownership = {
        "command_line": "command_line", "network_connection": "network_ownership",
        "module": "loaded_module", "memory_region": "memory_region",
        "thread": "thread", "signature_match": "signature_match",
        "handle": "handle",
    }
    for artifact in sorted(artifacts, key=lambda a: str(a.id)):
        owner = owners.get((artifact.analysis_run_id, artifact.pid))
        if owner is None:
            continue
        data = artifact_fields(artifact)
        source, target, kind = owner, artifact, ownership.get(artifact.artifact_type)
        if artifact.id == owner.id:
            try:
                parent_pid = int(data.get("ppid"))
            except (ValueError, TypeError):
                continue
            source = owners.get((artifact.analysis_run_id, parent_pid))
            kind = "parent_child"
            if source is None or source.id == target.id:
                continue
        elif artifact.artifact_type in ("process", "process_tree"):
            kind = "process_observation"
        if kind:
            links.append(ArtifactRelationship(
                source.id, target.id, kind, 1.0,
                {"kind": "observed", "source_reference": str(artifact.id),
                 "plugin_run_id": str(artifact.plugin_run_id), "provenance": artifact.provenance,
                 "explanation": "Captured PPID references the parent process."
                 if kind == "parent_child" else
                 "Captured PID associates this record with a process in the same analysis run; "
                 "this does not establish execution order or causation."},
            ))
    return links
