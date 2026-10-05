"""Validate and compose a manual layer without mutating analysis results."""

import json
from uuid import UUID

from memsentry.app.graph_service import GraphEdge, GraphNode, InvestigationGraph, load_graph
from memsentry.models.graph_revision import GraphDraft, GraphRevision
from memsentry.storage.database import Database
from memsentry.storage.repositories.graph_revision_repository import GraphRevisionRepository


def edge_key(edge: GraphEdge) -> str:
    return json.dumps([edge.source, edge.target, edge.label, edge.kind])


def validate_draft(baseline: InvestigationGraph, draft: GraphDraft) -> None:
    ids = baseline.nodes.keys() | draft.nodes.keys()
    if any(not key.startswith("hypothesis:") for key in draft.nodes):
        raise ValueError("Manual nodes must have hypothesis identifiers.")
    if baseline.nodes.keys() & draft.nodes.keys():
        raise ValueError("Hypotheses cannot replace captured nodes.")
    if not (draft.visible | draft.notes.keys() | draft.positions.keys()) <= ids:
        raise ValueError("The graph references nodes outside this analysis run.")
    seen = set()
    for node in draft.nodes.values():
        if not node.label.strip() or not node.category.strip() or not node.notes.strip():
            raise ValueError("A hypothesis needs a label, category, and rationale.")
    for edge in draft.edges:
        if edge.source not in ids or edge.target not in ids:
            raise ValueError("Relationship endpoints must belong to this analysis run.")
        if edge.source == edge.target:
            raise ValueError("Choose two different nodes to connect.")
        if not edge.label.strip() or not edge.rationale.strip():
            raise ValueError("A relationship type and rationale are required.")
        key = (edge.source, edge.target, edge.label.casefold().strip())
        if key in seen:
            raise ValueError("This manual relationship already exists.")
        seen.add(key)
    edges = {edge_key(e) for e in baseline.edges} | {
        edge_key(GraphEdge(e.source, e.target, e.label, "manual", {})) for e in draft.edges}
    if not draft.hidden_edges <= edges:
        raise ValueError("A hidden relationship is not part of this graph.")


def compose_graph(baseline: InvestigationGraph, draft: GraphDraft) -> InvestigationGraph:
    validate_draft(baseline, draft)
    graph = InvestigationGraph(dict(baseline.nodes), list(baseline.edges), list(baseline.warnings))
    for key, node in draft.nodes.items():
        graph.nodes[key] = GraphNode(key, node.label, "hypothesis", {
            "origin": "Investigator hypothesis — not captured evidence", **node.model_dump()})
    graph.edges.extend(GraphEdge(e.source, e.target, e.label, "manual", {
        "origin": "Investigator relationship", "rationale": e.rationale}) for e in draft.edges)
    return graph


def save_revision(database: Database, run_id: UUID, name: str,
                  investigator: str, draft: GraphDraft) -> GraphRevision:
    # Revalidate serialization and run membership at the persistence boundary.
    draft = GraphDraft.model_validate_json(draft.model_dump_json())
    validate_draft(load_graph(database, run_id), draft)
    return GraphRevisionRepository(database).create(run_id, name, investigator, draft)
