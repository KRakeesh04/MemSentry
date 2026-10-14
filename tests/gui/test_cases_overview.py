from threading import Event

import pytest
from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QLabel, QPushButton

from memsentry.app.case_service import create_case, generate_case_number, workspace_database
from memsentry.app.intake_service import IntakeRequest, IntakeService
from memsentry.gui.main_window import MainWindow
from memsentry.gui.pages.activity import ActivityPage
from memsentry.gui.pages.artifacts import ArtifactsPage
from memsentry.gui.pages.cases import CasesPage
from memsentry.gui.pages.evidence import EvidencePage
from memsentry.gui.pages.overview import OverviewPage
from memsentry.models.analysis_run import AnalysisRunCreate, HostOS
from memsentry.models.case import CaseStatus
from memsentry.models.evidence import IntegrityStatus
from memsentry.models.finding import FindingCreate, FindingSeverity
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.finding_repository import FindingRepository


def test_analysis_errors_are_summarized_with_expandable_originals(qtbot):
    from types import SimpleNamespace
    from uuid import uuid4

    page = OverviewPage()
    qtbot.addWidget(page)
    error = "module 'volatility3.framework.exceptions' has no attribute 'UnsatisfiedRequirementException'"
    original = f"process_list: {error}\nprocess_tree: {error}"
    page.run_choice.addItem("Failed run", SimpleNamespace(
        id=uuid4(), status="completed_with_errors", error_message=original))
    page.run_choice.setCurrentIndex(page.run_choice.count() - 1)
    page._run_changed()
    assert page.run_status.text().count("An application error") == 1
    assert "Completed with errors" in page.run_status.text()
    assert page.error_details.toPlainText() == original
    assert page.error_details.isHidden()
    page.error_details_toggle.click()
    assert not page.error_details.isHidden()
    page.run_choice.clear()
    page._run_changed()
    assert page.error_details.isHidden()
    assert page.error_details.toPlainText() == ""


@pytest.mark.parametrize("page_type", [ActivityPage, ArtifactsPage])
def test_run_picker_formats_uuid_identifiers(qtbot, tmp_path, page_type):
    source = tmp_path / "synthetic.mem"
    source.write_bytes(b"synthetic memory only")
    result = IntakeService().run(
        IntakeRequest(tmp_path, "CASE-1", "Test", source), lambda *_: None, Event()
    )
    database = workspace_database(tmp_path)
    case = CaseRepository(database).get_by_id(result.evidence.case_id)
    run = AnalysisRunRepository(database).create(
        AnalysisRunCreate(
            evidence_id=result.evidence.id,
            application_version="test",
            volatility_version="test",
            host_os=HostOS.LINUX,
        )
    )
    page = page_type()
    qtbot.addWidget(page)
    page.open_case(str(tmp_path), case)
    page.evidence_combo.setCurrentIndex(1)
    assert page.run_combo.count() == 2
    assert str(run.id)[:8] in page.run_combo.itemText(1)
    assert page.run_combo.itemData(1).id == run.id


@pytest.fixture(autouse=True)
def isolated_settings(tmp_path, monkeypatch):
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)
    for module in ("cases", "evidence"):
        monkeypatch.setattr(f"memsentry.gui.pages.{module}.QSettings", lambda *_: settings)


def test_suggested_numbers_are_editable_and_refresh_preserves_custom(qtbot, tmp_path):
    assert generate_case_number() != generate_case_number()
    page = EvidencePage()
    qtbot.addWidget(page)
    assert page.case_number.text().startswith("CASE-")
    assert not page.case_number.isReadOnly()
    page.case_number.setText("CUSTOM-01")
    page.case_name.setText("My case")
    page.workspace.setText(str(tmp_path))
    page._load_cases()
    assert page.case_number.text() == "CUSTOM-01"
    assert page.case_name.text() == "My case"


def test_cases_create_filter_open_and_reject_duplicates(qtbot, tmp_path):
    page = CasesPage()
    qtbot.addWidget(page)
    page.workspace.setText(str(tmp_path))
    page.number.setText("CUSTOM-01")
    page.name.setText("Workstation investigation")
    with qtbot.waitSignal(page.case_opened) as signal:
        page.create_button.click()
    assert signal.args[0] == str(tmp_path)
    assert signal.args[1].case_number == "CUSTOM-01"
    assert page.table.rowCount() == 1
    page.search.setText("no match")
    assert page.table.rowCount() == 0
    page.search.clear()
    page.table.selectRow(0)
    with qtbot.waitSignal(page.case_opened):
        page.open_button.click()
    page.number.setText("CUSTOM-01")
    page.name.setText("Duplicate")
    page.create_button.click()
    assert "already exists" in page.message.text()
    page.workspace.setText(str(tmp_path / "missing"))
    assert page.table.rowCount() == 0
    assert not page.open_button.isEnabled()
    page.refresh()
    assert "Could not load cases" in page.message.text()


def test_overview_empty_closed_case_and_intake_selection(qtbot, tmp_path):
    case = create_case(str(tmp_path), "CASE-1", "<b>Literal case name</b>", "notes")
    window = MainWindow()
    qtbot.addWidget(window)
    window._open_case(str(tmp_path), case)
    assert window.pages.currentIndex() == 1
    assert window.overview_page.title.text() == case.name
    assert "No evidence" in window.overview_page.integrity.text()
    window.overview_page.import_button.click()
    assert window.pages.currentIndex() == 2
    assert window.evidence_page.case_number.text() == case.case_number
    assert window.evidence_page.case_number.isReadOnly()
    window.evidence_page.existing_cases.setCurrentIndex(0)
    assert window.evidence_page.case_number.text().startswith("CASE-")
    assert not window.evidence_page.case_number.isReadOnly()
    CaseRepository(workspace_database(tmp_path)).change_status(case.id, CaseStatus.CLOSED)
    assert not window.evidence_page.use_case(str(tmp_path), case)
    window.overview_page.refresh()
    assert not window.overview_page.import_button.isEnabled()


def test_overview_scopes_findings_and_shows_saved_integrity(qtbot, tmp_path):
    source = tmp_path / "synthetic.mem"
    source.write_bytes(b"synthetic memory only")
    result = IntakeService().run(
        IntakeRequest(tmp_path, "CASE-1", "Test", source), lambda *_: None, Event()
    )
    database = workspace_database(tmp_path)
    case = CaseRepository(database).get_by_id(result.evidence.case_id)
    runs = AnalysisRunRepository(database)
    old = runs.create(
        AnalysisRunCreate(
            evidence_id=result.evidence.id,
            application_version="test",
            volatility_version="test",
            host_os=HostOS.LINUX,
        )
    )
    FindingRepository(database).create(
        FindingCreate(
            analysis_run_id=old.id,
            rule_id="TEST",
            title="Synthetic finding",
            description="Test fixture only",
            severity=FindingSeverity.HIGH,
            confidence=0.8,
        )
    )
    runs.mark_completed(old.id)
    latest = runs.create(
        AnalysisRunCreate(
            evidence_id=result.evidence.id,
            application_version="test",
            volatility_version="test",
            host_os=HostOS.LINUX,
        )
    )
    runs.mark_failed(latest.id, "Synthetic plugin failure")
    page = OverviewPage()
    qtbot.addWidget(page)
    page.open_case(str(tmp_path), case)
    assert result.evidence.sha256 in page.hash.text()
    assert "Last recorded: verified" in page.integrity.text()
    assert "Synthetic plugin failure" in page.error_details.toPlainText()
    assert "No findings" in page.findings_layout.itemAt(0).widget().text()
    page.run_choice.setCurrentIndex(1)
    findings_summary = page.findings_layout.itemAt(0).widget()
    assert any(
        "Total findings: 1" in item.text()
        for item in findings_summary.findChildren(QLabel)
    )
    assert any(
        "High: 1" in item.text()
        for item in findings_summary.findChildren(QLabel)
    )
    assert any(
        button.text() == "View findings"
        for button in findings_summary.findChildren(QPushButton)
    )
    EvidenceRepository(database).update_integrity_status(
        result.evidence.id, IntegrityStatus.MODIFIED
    )
    page.refresh()
    assert page.integrity.objectName() == "integrityWarning"
    assert "modified" in page.workflow.text()


def test_import_refreshes_cases_and_overview_without_leaving_intake(qtbot, tmp_path):
    window = MainWindow()
    qtbot.addWidget(window)
    page = window.evidence_page
    source = tmp_path / "fixture.mem"
    source.write_bytes(b"synthetic evidence")
    page.workspace.setText(str(tmp_path))
    page.case_name.setText("Imported case")
    page.source.setText(str(source))
    window.sidebar.setCurrentRow(2)
    with qtbot.waitSignal(page.evidence_registered, timeout=5000):
        page.start.click()
    qtbot.waitUntil(lambda: page.worker is None)
    assert window.cases_page.table.rowCount() == 1
    assert window.overview_page.evidence_choice.count() == 1
    assert window.pages.currentIndex() == 2
    assert window.overview_page.case.name == "Imported case"


def test_workspace_and_status_filters_do_not_leak_cases(qtbot, tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    first.mkdir()
    second.mkdir()
    case = create_case(str(first), "PRIVATE", "First workspace", "")
    CaseRepository(workspace_database(first)).change_status(case.id, CaseStatus.CLOSED)
    page = CasesPage()
    qtbot.addWidget(page)
    page.workspace.setText(str(first))
    page.refresh()
    page.status.setCurrentText("Open")
    assert page.table.rowCount() == 0
    page.status.setCurrentText("Closed")
    assert page.table.rowCount() == 1
    page.workspace.setText(str(second))
    page.refresh()
    assert page.table.rowCount() == 0
    assert not (second / "memsentry.sqlite3").exists()


def test_missing_overview_database_does_not_create_one(qtbot, tmp_path):
    case = create_case(str(tmp_path), "ONE", "Test", "")
    other = tmp_path / "empty"
    other.mkdir()
    page = OverviewPage()
    qtbot.addWidget(page)
    page.open_case(str(other), case)
    assert "no longer available" in page.error.text()
    assert not (other / "memsentry.sqlite3").exists()
    assert not page.import_button.isEnabled()
