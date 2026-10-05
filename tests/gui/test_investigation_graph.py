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


def test_graph_navigation_selection_movement_and_run_isolation(qtbot, tmp_path, monkeypatch):
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
    monkeypatch.setattr(page, "confirm_discard", lambda: True)
    page.run_choice.setCurrentIndex(page.run_choice.findData(str(other.id)))
    assert page.run_choice.currentData() == str(other.id)
    assert not page.graph.nodes
    assert not page.scene.items()
    assert "No captured" in page.status.text()


def test_finding_opens_graph_and_navigation_preserves_layout(qtbot, tmp_path, monkeypatch):
    _, case, run, _, finding = graph_fixture(tmp_path)
    window = MainWindow()
    qtbot.addWidget(window)
    monkeypatch.setattr(window.graph_page, "confirm_discard", lambda: True)
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


def test_manual_revision_round_trip_preserves_evidence_and_history(qtbot, tmp_path):
    from memsentry.storage.repositories.graph_revision_repository import GraphRevisionRepository

    db, case, run, artifacts, finding = graph_fixture(tmp_path)
    baseline = load_graph(db, run.id)
    page = InvestigationGraphPage()
    qtbot.addWidget(page)
    page.open_case(str(tmp_path), case)
    node = page.add_hypothesis("Suspected payload", "File", "Referenced by suspicious command")
    page.connect_nodes(str(artifacts[1].id), node, "may load", "Requires confirmation")
    assert page.dirty
    assert len(page.graph.edges) == len(baseline.edges) + 1
    page.undo()
    assert len(page.graph.edges) == len(baseline.edges)
    page.redo()
    page.node_items[node].moveBy(91, 42)
    position = page.node_items[node].pos()
    page.draft.notes[str(finding.id)] = "Review this finding with the analyst"
    page.capture_edit()
    page.scene.clearSelection()
    page.node_items[str(finding.id)].setSelected(True)
    page.hide_selected()
    assert str(finding.id) not in page.visible
    page.save_current("Payload hypothesis", "Test investigator")
    assert not page.dirty
    first_id = page._revision_id
    page.node_items[node].moveBy(10, 0)
    page.save_current("Second revision", "Another investigator")
    revisions = GraphRevisionRepository(db).list_by_run(run.id)
    assert len(revisions) == 2
    assert revisions[1].draft.positions[node] == (position.x(), position.y())
    assert revisions[0].draft.positions[node] != revisions[1].draft.positions[node]
    reopened = InvestigationGraphPage()
    qtbot.addWidget(reopened)
    reopened.open_case(str(tmp_path), case)
    reopened.revision_choice.setCurrentIndex(reopened.revision_choice.findData(first_id))
    assert not reopened.dirty
    assert reopened.node_items[node].pos() == position
    assert str(finding.id) not in reopened.visible
    assert reopened.draft.notes[str(finding.id)].startswith("Review")
    assert reopened.graph.nodes[node].kind == "hypothesis"
    assert any(e.kind == "manual" and e.target == node for e in reopened.graph.edges)
    assert load_graph(db, run.id) == baseline
    assert FindingRepository(db).get_by_id(finding.id) == finding
    assert ArtifactRepository(db).list_by_analysis_run(run.id) == artifacts
    assert (tmp_path / "synthetic.mem").read_bytes() == b"synthetic graph evidence"


def test_invalid_links_failed_saves_and_cancel_preserve_draft(qtbot, tmp_path, monkeypatch):
    import pytest
    from PySide6.QtWidgets import QMessageBox

    from memsentry.storage.repositories.graph_revision_repository import GraphRevisionRepository

    db, case, run, artifacts, _ = graph_fixture(tmp_path)
    page = InvestigationGraphPage()
    qtbot.addWidget(page)
    page.open_case(str(tmp_path), case)
    key = page.add_hypothesis("Remote host", "Network", "Unconfirmed host")
    before = page.snapshot()
    for source, target, label, reason in [
        (key, key, "same", "invalid"), (str(uuid4()), key, "cross run", "invalid"),
        (str(artifacts[0].id), key, " ", "reason"),
        (str(artifacts[0].id), key, "type", " "),
    ]:
        with pytest.raises(ValueError):
            page.connect_nodes(source, target, label, reason)
        assert page.snapshot() == before
    page.connect_nodes(str(artifacts[0].id), key, "contacts", "Recorded hypothesis")
    with pytest.raises(ValueError, match="already exists"):
        page.connect_nodes(str(artifacts[0].id), key, "contacts", "Duplicate")
    before = page.snapshot()

    def fail(*args):
        raise OSError("Disk unavailable")

    monkeypatch.setattr(GraphRevisionRepository, "create", fail)
    with pytest.raises(OSError, match="Disk unavailable"):
        page.save_current("Draft", "Investigator")
    assert page.snapshot() == before
    assert page.dirty
    assert not GraphRevisionRepository(db).list_by_run(run.id)
    monkeypatch.setattr(QMessageBox, "question", lambda *a: QMessageBox.StandardButton.Cancel)
    other = AnalysisRunRepository(db).create(AnalysisRunCreate(
        evidence_id=run.evidence_id, application_version="test", volatility_version="test",
        host_os=HostOS.LINUX))
    page.refresh()
    assert page.snapshot() == before
    page.run_choice.setCurrentIndex(page.run_choice.findData(str(other.id)))
    assert page.run_choice.currentData() == str(run.id)
    assert page.snapshot() == before


def test_revisions_are_immutable_and_run_scoped(tmp_path):
    import sqlite3

    import pytest

    from memsentry.app.graph_revision_service import save_revision
    from memsentry.models.graph_revision import GraphDraft
    from memsentry.storage.repositories.graph_revision_repository import GraphRevisionRepository

    db, _, run, artifacts, _ = graph_fixture(tmp_path)
    draft = GraphDraft(visible={str(artifacts[0].id)})
    revision = save_revision(db, run.id, "Review", "Analyst", draft)
    with db.transaction() as connection, pytest.raises(sqlite3.IntegrityError, match="immutable"):
        connection.execute("UPDATE graph_revisions SET name = 'changed' WHERE id = ?",
                           (str(revision.id),))
    with db.transaction() as connection, pytest.raises(sqlite3.IntegrityError, match="immutable"):
        connection.execute("DELETE FROM graph_revisions WHERE id = ?", (str(revision.id),))
    other = AnalysisRunRepository(db).create(AnalysisRunCreate(
        evidence_id=run.evidence_id, application_version="test", volatility_version="test",
        host_os=HostOS.LINUX))
    with pytest.raises(ValueError, match="outside this analysis run"):
        save_revision(db, other.id, "Invalid reference", "Analyst", draft)
    assert not GraphRevisionRepository(db).list_by_run(other.id)


def test_case_switch_and_close_protect_draft(qtbot, tmp_path, monkeypatch):
    from PySide6.QtGui import QCloseEvent
    from PySide6.QtWidgets import QMessageBox

    from memsentry.models.case import CaseCreate

    db, case, _, _, _ = graph_fixture(tmp_path)
    other = CaseRepository(db).create(CaseCreate(case_number="EMPTY", name="Empty case"))
    window = MainWindow()
    qtbot.addWidget(window)
    window._open_case(str(tmp_path), case)
    window.graph_page.add_hypothesis("Host", "Network", "Needs review")
    draft = window.graph_page.snapshot()
    monkeypatch.setattr(QMessageBox, "question", lambda *a: QMessageBox.StandardButton.Cancel)
    window._open_case(str(tmp_path), other)
    assert window.findings_page.case == case
    assert window.graph_page.case == case
    assert window.graph_page.snapshot() == draft
    event = QCloseEvent()
    window.closeEvent(event)
    assert not event.isAccepted()
    monkeypatch.setattr(QMessageBox, "question", lambda *a: QMessageBox.StandardButton.Discard)
    window._open_case(str(tmp_path), other)
    assert window.graph_page.case == other
    assert not window.graph_page.graph.nodes
    assert not window.graph_page.scene.items()
    assert not window.graph_page.dirty
    assert not window.graph_page.save_button.isEnabled()


def test_theme_cards_and_hidden_relationship_restore(qtbot, tmp_path, qapp):
    from PySide6.QtGui import QColor, QPalette

    from memsentry.app.graph_revision_service import edge_key
    from memsentry.gui.theme import workspace_stylesheet

    _, case, _, _, _ = graph_fixture(tmp_path)
    page = InvestigationGraphPage()
    qtbot.addWidget(page)
    page.setObjectName("workspace")
    page.resize(1400, 1000)
    page.open_case(str(tmp_path), case)
    page.show()
    edge = page._visible_edges[0]
    page.edge_items[0][1].setSelected(True)
    page.hide_selected()
    assert edge_key(edge) in page.draft.hidden_edges
    assert edge not in page._visible_edges
    page.undo()
    assert edge in page._visible_edges
    initial = qapp.palette()
    try:
        for name, background, edge_color in [("light", "#F1F5F9", "#526174"),
                                               ("dark", "#11151C", "#A5B0C0")]:
            palette = QPalette(initial)
            palette.setColor(QPalette.ColorRole.Window, QColor(background))
            qapp.setPalette(palette)
            page.setStyleSheet(workspace_stylesheet())
            qtbot.wait(20)
            page.grab().save(str(tmp_path / f"graph-{name}.png"))
            assert page.edge_items[0][1].pen().color() == QColor(edge_color)
    finally:
        qapp.setPalette(initial)
