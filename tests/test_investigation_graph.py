"""Targeted tests for Investigation Graph data models and builder service."""

from __future__ import annotations

from pathlib import Path
from threading import Event
from uuid import uuid4

from memsentry.app.case_service import workspace_database
from memsentry.app.intake_service import IntakeRequest, IntakeService
from memsentry.graph.builder import GraphBuilder
from memsentry.graph.models import GraphData, GraphEdge, GraphNode
from memsentry.models.analysis_run import AnalysisRunCreate, HostOS
from memsentry.models.artifact import ArtifactCreate
from memsentry.models.finding import FindingCreate, FindingSeverity
from memsentry.models.plugin_run import PluginRunCreate, PluginRunStatus
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.finding_repository import FindingRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository


def test_graph_data_deduplication():
    graph = GraphData()
    n1 = GraphNode(id="n1", node_type="process", label="proc1")
    n2 = GraphNode(id="n2", node_type="process", label="proc2")
    graph.add_node(n1)
    graph.add_node(n2)

    e1 = GraphEdge(source_id="n1", target_id="n2", label="spawned", relationship_type="parent_of")
    e2 = GraphEdge(source_id="n1", target_id="n2", label="spawned", relationship_type="parent_of")
    graph.add_edge(e1)
    graph.add_edge(e2)

    assert len(graph.edges) == 1
    assert graph.edges[0].source_id == "n1"


def test_graph_builder_empty_case(tmp_path: Path):
    source = tmp_path / "memory.mem"
    source.write_bytes(b"test memory image")
    result = IntakeService().run(
        IntakeRequest(tmp_path, "CASE-GRAPH", "Graph Test Case", source),
        lambda *_: None,
        Event(),
    )
    database = workspace_database(tmp_path)
    case = CaseRepository(database).get_by_id(result.evidence.case_id)
    assert case is not None

    graph = GraphBuilder.build_for_case(tmp_path, case)
    # Should contain 1 evidence node, 0 processes, 0 edges
    assert len(graph.nodes) == 1
    ev_node = list(graph.nodes.values())[0]
    assert ev_node.node_type == "evidence"
    assert ev_node.label == "memory.mem"
    assert len(graph.edges) == 0


def test_graph_builder_entities_and_relationships(tmp_path: Path):
    source = tmp_path / "memory.mem"
    source.write_bytes(b"test memory image")
    result = IntakeService().run(
        IntakeRequest(tmp_path, "CASE-GRAPH-2", "Graph Test Case 2", source),
        lambda *_: None,
        Event(),
    )
    database = workspace_database(tmp_path)
    case = CaseRepository(database).get_by_id(result.evidence.case_id)
    assert case is not None

    run = AnalysisRunRepository(database).create(
        AnalysisRunCreate(
            evidence_id=result.evidence.id,
            application_version="0.1.0",
            volatility_version="3.0.0",
            host_os=HostOS.LINUX,
        )
    )
    plugin_run = PluginRunRepository(database).create(
        PluginRunCreate(
            analysis_run_id=run.id,
            plugin_name="pslist",
            status=PluginRunStatus.COMPLETED,
        )
    )

    art_repo = ArtifactRepository(database)
    # 1. Parent process: PID 100
    p1 = art_repo.create(
        ArtifactCreate(
            analysis_run_id=run.id,
            plugin_run_id=plugin_run.id,
            artifact_type="process",
            pid=100,
            original_data={
                "normalized": {
                    "pid": 100,
                    "ppid": None,
                    "process_name": "parent.exe",
                }
            },
            provenance={"plugin": "pslist"},
        )
    )

    # 2. Child process: PID 200, PPID 100
    p2 = art_repo.create(
        ArtifactCreate(
            analysis_run_id=run.id,
            plugin_run_id=plugin_run.id,
            artifact_type="process",
            pid=200,
            original_data={
                "normalized": {
                    "pid": 200,
                    "ppid": 100,
                    "process_name": "child.exe",
                }
            },
            provenance={"plugin": "pslist"},
        )
    )

    # 3. Network connection: PID 200 connecting to 192.168.1.50:443
    art_repo.create(
        ArtifactCreate(
            analysis_run_id=run.id,
            plugin_run_id=plugin_run.id,
            artifact_type="network_connection",
            pid=200,
            original_data={
                "normalized": {
                    "pid": 200,
                    "local_address": "10.0.0.5",
                    "local_port": 50000,
                    "remote_address": "192.168.1.50",
                    "remote_port": 443,
                    "protocol": "TCP",
                    "state": "ESTABLISHED",
                }
            },
            provenance={"plugin": "netscan"},
        )
    )

    # 4. Finding linked with evidence to Child process (p2)
    FindingRepository(database).create_many_with_evidence(
        [
            (
                FindingCreate(
                    analysis_run_id=run.id,
                    rule_id="SUSPICIOUS-SPAWN",
                    title="Suspicious child process",
                    description="Child spawned suspiciously",
                    severity=FindingSeverity.HIGH,
                    confidence=0.9,
                ),
                [p2],
            )
        ]
    )

    graph = GraphBuilder.build_for_case(tmp_path, case)

    # Verify node types: 1 evidence, 2 processes, 1 network, 1 finding = 5 nodes
    node_types = [n.node_type for n in graph.nodes.values()]
    assert node_types.count("evidence") == 1
    assert node_types.count("process") == 2
    assert node_types.count("network") == 1
    assert node_types.count("finding") == 1

    # Verify relationships:
    # - evidence -> process 100
    # - evidence -> process 200
    # - process 100 -> process 200 (parent_of)
    # - process 200 -> network (network_traffic)
    # - finding -> process 200 (flagged_process)
    rel_types = [e.relationship_type for e in graph.edges]
    assert "contains_process" in rel_types
    assert "parent_of" in rel_types
    assert "network_traffic" in rel_types
    assert "flagged_process" in rel_types


def test_investigation_graph_page_gui(qtbot, tmp_path: Path):
    from memsentry.gui.pages.investigation_graph import InvestigationGraphPage

    source = tmp_path / "memory.mem"
    source.write_bytes(b"test memory image")
    result = IntakeService().run(
        IntakeRequest(tmp_path, "CASE-GRAPH-UI", "Graph UI Test Case", source),
        lambda *_: None,
        Event(),
    )
    database = workspace_database(tmp_path)
    case = CaseRepository(database).get_by_id(result.evidence.case_id)

    page = InvestigationGraphPage()
    qtbot.addWidget(page)

    # Empty state before case opened
    assert "No case selected" in page.status_metrics.text()

    # Open case
    page.open_case(str(tmp_path), case)
    assert "1 Entities" in page.status_metrics.text()
    assert "0 Relationships" in page.status_metrics.text()

    # Search filter testing
    page.search_input.setText("nonexistent")
    assert "0 Entities" in page.status_metrics.text()

    page.search_input.setText("memory")
    assert "1 Entities" in page.status_metrics.text()
