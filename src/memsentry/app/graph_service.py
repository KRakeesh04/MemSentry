"""Read-only graph projection of a selected persisted analysis run."""

from dataclasses import dataclass, field
from typing import Any
from uuid import UUID

from memsentry.correlation.relationships import artifact_fields, observed_relationships
from memsentry.storage.database import Database
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.finding_evidence_repository import FindingEvidenceRepository
from memsentry.storage.repositories.finding_repository import FindingRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.storage.repositories.relationship_repository import RelationshipRepository


@dataclass
class GraphNode:
    id: str
    label: str
    kind: str
    details: dict[str, Any]


@dataclass
class GraphEdge:
    source: str
    target: str
    label: str
    kind: str
    details: dict[str, Any]


@dataclass
class InvestigationGraph:
    nodes: dict[str, GraphNode] = field(default_factory=dict)
    edges: list[GraphEdge] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    def neighborhood(
        self, seeds: set[str], limit: int = 40, existing: set[str] | None = None
    ) -> set[str]:
        visible = seeds & self.nodes.keys()
        neighbors = {endpoint for edge in self.edges
                     if edge.source in visible or edge.target in visible
                     for endpoint in (edge.source, edge.target)}
        return visible | set(sorted(neighbors - visible - (existing or set()))[:limit])


def load_graph(database: Database, run_id: UUID) -> InvestigationGraph:
    graph = InvestigationGraph()
    artifacts = ArtifactRepository(database).list_by_analysis_run(run_id)
    plugins = {str(p.id): p for p in PluginRunRepository(database).list_by_analysis_run(run_id)}
    for plugin in plugins.values():
        if plugin.status != "completed":
            graph.warnings.append(
                f"Coverage incomplete: {plugin.plugin_name} is {plugin.status}. "
                f"{plugin.error_message or ''}"
            )
    by_id = {str(a.id): a for a in artifacts}
    for artifact in artifacts:
        data = artifact_fields(artifact)
        name = next((str(data[k]) for k in (
            "process_name", "command_line", "remote_address", "path", "rule_name", "start"
        ) if data.get(k) is not None), artifact.artifact_type.replace("_", " "))
        label = f"{name[:70]} · PID {artifact.pid}" if artifact.pid is not None else name[:70]
        details = artifact.model_dump(mode="json")
        plugin = plugins.get(str(artifact.plugin_run_id))
        details["plugin_output"] = plugin.model_dump(mode="json") if plugin else None
        graph.nodes[str(artifact.id)] = GraphNode(str(artifact.id), label, artifact.artifact_type, details)
    relationships = RelationshipRepository(database).load_baseline(run_id)
    if relationships is None:
        relationships = observed_relationships(artifacts)
        graph.warnings.append("Legacy run: observed relationships reconstructed from stored artifacts "
                              "using observed-v1; no saved relationship baseline exists.")
    for relationship in relationships:
        if (str(relationship.source_artifact_id) not in graph.nodes
                or str(relationship.target_artifact_id) not in graph.nodes):
            graph.warnings.append("Saved relationship has an unresolved endpoint; omitted.")
            continue
        graph.edges.append(GraphEdge(
            str(relationship.source_artifact_id), str(relationship.target_artifact_id),
            relationship.relationship_type.replace("_", " "), "observed", relationship.metadata,
        ))
    for finding in FindingRepository(database).list_by_analysis_run(run_id):
        key = str(finding.id)
        details = finding.model_dump(mode="json")
        details["limitations"] = (
            "Stored heuristic triage result, not a malware probability. Exact trigger artifacts, "
            "rule version, score contribution, and completeness are not recorded by this baseline. "
            "Parent-child and YARA-region rules require investigator review; MS-R008 is not implemented."
        )
        graph.nodes[key] = GraphNode(key, f"{finding.rule_id}: {finding.title}", "finding", details)
        evidence = FindingEvidenceRepository(database).list_by_finding(finding.id)
        if not evidence:
            graph.warnings.append(f"{finding.rule_id}: supporting artifact links not recorded.")
        for item in evidence:
            reference = str(item.supporting_data.get("artifact_id") or item.source_reference)
            artifact = by_id.get(reference)
            if artifact is None or artifact.plugin_run_id != item.plugin_run_id:
                graph.warnings.append(f"{finding.rule_id}: unresolved supporting artifact {reference}.")
                continue
            graph.edges.append(GraphEdge(
                reference, key, f"context for {finding.rule_id}", "inferred",
                {"rule_id": finding.rule_id, "explanation": item.explanation,
                 "source_reference": reference, "plugin_run_id": str(item.plugin_run_id),
                 "provenance": artifact.provenance,
                 "limitation": "Stored process context is not necessarily the exact rule trigger. "
                 "A triage finding does not prove causation or malicious activity."},
            ))
    return graph
