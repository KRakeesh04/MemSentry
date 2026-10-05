"""Synthetic graph provenance and interaction checks; no real evidence is opened."""

from threading import Event
from uuid import uuid4

from memsentry.app.case_service import workspace_database
from memsentry.app.graph_service import load_graph
from memsentry.app.intake_service import IntakeRequest, IntakeService
from memsentry.correlation.relationships import observed_relationships
from memsentry.gui.main_window import MainWindow
from memsentry.gui.pages.investigation_graph import InvestigationGraphPage
from memsentry.models.analysis_run import AnalysisRunCreate, HostOS
from memsentry.models.artifact import ArtifactCreate
from memsentry.models.finding import FindingCreate, FindingSeverity
from memsentry.models.finding_evidence import FindingEvidenceCreate
from memsentry.models.plugin_run import PluginRunCreate
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.finding_evidence_repository import FindingEvidenceRepository
from memsentry.storage.repositories.finding_repository import FindingRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository


def graph_fixture(tmp_path):
    source = tmp_path / "synthetic.mem"
    source.write_bytes(b"synthetic graph evidence")
    intake = IntakeService().run(
        IntakeRequest(tmp_path, "GRAPH-1", "Graph test", source), lambda *_: None, Event())
    db = workspace_database(tmp_path)
    case = CaseRepository(db).get_by_id(intake.evidence.case_id)
    run = AnalysisRunRepository(db).create(AnalysisRunCreate(
        evidence_id=intake.evidence.id, application_version="test",
        volatility_version="test", host_os=HostOS.LINUX))
    plugin = PluginRunRepository(db).create(PluginRunCreate(
        analysis_run_id=run.id, plugin_name="synthetic"))
    artifacts = ArtifactRepository(db).create_many([
        ArtifactCreate(analysis_run_id=run.id, plugin_run_id=plugin.id,
                       artifact_type=kind, pid=pid, original_data={"normalized": data},
                       provenance={"source_row": index})
        for index, (kind, pid, data) in enumerate([
            ("process", 1, {"process_name": "parent", "ppid": 0}),
            ("process", 2, {"process_name": "child", "ppid": 1}),
            ("command_line", 2, {"command_line": "curl example.invalid"}),
            ("network_connection", 2, {"remote_address": "192.0.2.1"}),
            ("network_connection", 999, {"remote_address": "192.0.2.2"}),
        ])])
    finding = FindingRepository(db).create_many_with_evidence([(
        FindingCreate(analysis_run_id=run.id, rule_id="TEST", title="Synthetic finding",
                      description="Test inference", severity=FindingSeverity.MEDIUM),
        artifacts[1:4])])[0]
    return db, case, run, artifacts, finding


def test_graph_links_real_artifacts_and_preserves_baseline(tmp_path):
    db, _, run, artifacts, finding = graph_fixture(tmp_path)
    graph = load_graph(db, run.id)
    assert len(graph.nodes) == 6
    assert len(graph.edges) == 6
    assert all(e.source in graph.nodes and e.target in graph.nodes for e in graph.edges)
    parent = next(e for e in graph.edges if e.label == "parent child")
    assert (parent.source, parent.target) == (str(artifacts[0].id), str(artifacts[1].id))
    assert not any(str(artifacts[-1].id) in (e.source, e.target) for e in graph.edges)
    assert all(e.kind == "inferred" for e in graph.edges if e.target == str(finding.id))
    assert FindingRepository(db).get_by_id(finding.id) == finding
    assert ArtifactRepository(db).list_by_analysis_run(run.id) == artifacts


def test_relationships_omit_ambiguous_and_cross_run_ownership(tmp_path):
    _, _, _, artifacts, _ = graph_fixture(tmp_path)
    cross_run = artifacts[3].model_copy(update={"analysis_run_id": uuid4()})
    assert not any(e.target_artifact_id == cross_run.id
                   for e in observed_relationships([*artifacts[:3], cross_run]))
    duplicate = artifacts[1].model_copy(update={"id": uuid4()})
    assert not any(e.relationship_type == "network_ownership"
                   for e in observed_relationships([*artifacts, duplicate]))


def test_unresolved_finding_reference_is_visible_not_fabricated(tmp_path):
    db, _, run, artifacts, finding = graph_fixture(tmp_path)
    FindingEvidenceRepository(db).create(FindingEvidenceCreate(
        finding_id=finding.id, plugin_run_id=artifacts[0].plugin_run_id,
        source_reference=str(uuid4()), explanation="Legacy unresolved reference"))
    graph = load_graph(db, run.id)
    assert len(graph.edges) == 6
    assert any("unresolved" in warning for warning in graph.warnings)


def test_graph_navigation_selection_movement_and_run_isolation(qtbot, tmp_path):
    db, case, run, artifacts, finding = graph_fixture(tmp_path)
    page = InvestigationGraphPage()
    qtbot.addWidget(page)
    page.resize(1200, 800)
    page.show()
    page.open_case(str(tmp_path), case)
    assert page.run_choice.currentData() == str(run.id)
    assert len(page.visible) == 4
    page.search.setText("parent")
    assert page.node_list.count() == 1
    page.node_list.setCurrentRow(0)
    page.focus_result()
    assert page.visible == {str(artifacts[0].id), str(artifacts[1].id)}
    node = page.node_items[str(artifacts[0].id)]
    assert "source_row" in page.inspector.toPlainText()
    before = page.edge_items[0][1].line()
    node.moveBy(50, 30)
    assert page.edge_items[0][1].line() != before
    page.relationships.setCurrentCell(0, 0)
    assert "OBSERVED" in page.inspector.toPlainText()
    page.node_items[str(artifacts[1].id)].setSelected(True)
    page.expand_selected()
    assert str(finding.id) in page.visible
    other = AnalysisRunRepository(db).create(AnalysisRunCreate(
        evidence_id=run.evidence_id, application_version="test", volatility_version="test",
        host_os=HostOS.LINUX))
    page.refresh()
    page.run_choice.setCurrentIndex(page.run_choice.findData(str(other.id)))
    assert page.run_choice.currentData() == str(other.id)
    assert not page.graph.nodes
    assert not page.scene.items()
    assert "No captured" in page.status.text()


def test_finding_opens_graph_and_navigation_preserves_layout(qtbot, tmp_path):
    _, case, run, _, finding = graph_fixture(tmp_path)
    window = MainWindow()
    qtbot.addWidget(window)
    window._open_case(str(tmp_path), case)
    assert window.findings_page.case == case
    window.findings_page.graph_requested.emit(run.id, finding.id)
    assert window.pages.currentIndex() == 5
    item = window.graph_page.node_items[str(finding.id)]
    item.moveBy(80, 40)
    position = item.pos()
    window.sidebar.setCurrentRow(4)
    window.sidebar.setCurrentRow(5)
    assert window.graph_page.node_items[str(finding.id)].pos() == position


def test_saved_baseline_is_immutable_and_validates_endpoints(tmp_path):
    import sqlite3
    from dataclasses import replace

    import pytest

    from memsentry.storage.repositories.relationship_repository import RelationshipRepository

    db, _, run, artifacts, _ = graph_fixture(tmp_path)
    repository = RelationshipRepository(db)
    links = observed_relationships(artifacts)
    with pytest.raises(ValueError, match="baseline run"):
        repository.create_baseline(run.id, [replace(links[0], target_artifact_id=uuid4())])
    assert repository.load_baseline(run.id) is None
    repository.create_baseline(run.id, links)
    assert {(e.source_artifact_id, e.target_artifact_id) for e in repository.load_baseline(run.id)} == {
        (e.source_artifact_id, e.target_artifact_id) for e in links}
    with pytest.raises(sqlite3.IntegrityError):
        repository.create_baseline(run.id, [])
    graph = load_graph(db, run.id)
    assert not any("reconstructed" in warning for warning in graph.warnings)
    assert len(graph.edges) == 6


def test_incremental_expansion_reaches_neighbors_beyond_first_batch():
    from memsentry.app.graph_service import GraphEdge, GraphNode, InvestigationGraph

    graph = InvestigationGraph()
    graph.nodes = {str(i): GraphNode(str(i), str(i), "process", {}) for i in range(100)}
    graph.edges = [GraphEdge("0", str(i), "test", "observed", {}) for i in range(1, 100)]
    first = graph.neighborhood({"0"})
    assert len(first) == 41
    second = first | graph.neighborhood({"0"}, existing=first)
    assert len(second) == 81
    assert len(second | graph.neighborhood({"0"}, existing=second)) == 100
