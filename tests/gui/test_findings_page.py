from __future__ import annotations

from threading import Event

from PySide6.QtWidgets import QLabel

from memsentry.app.case_service import workspace_database
from memsentry.app.intake_service import IntakeRequest, IntakeService
from memsentry.gui.pages.findings import FindingsPage
from memsentry.models.analysis_run import AnalysisRunCreate, HostOS
from memsentry.models.finding import FindingCreate, FindingSeverity
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.finding_repository import FindingRepository


def create_workspace_case(tmp_path):
    source = tmp_path / "memory.mem"
    source.write_bytes(b"test memory image")
    result = IntakeService().run(
        IntakeRequest(tmp_path, "CASE-1", "Test investigation", source),
        lambda *_: None,
        Event(),
    )
    database = workspace_database(tmp_path)
    case = CaseRepository(database).get_by_id(result.evidence.case_id)
    assert case is not None
    return database, case, result.evidence


def test_findings_page_loads_recorded_findings(qtbot, tmp_path):
    database, case, evidence = create_workspace_case(tmp_path)
    run = AnalysisRunRepository(database).create(
        AnalysisRunCreate(
            evidence_id=evidence.id,
            application_version="test",
            volatility_version="test",
            host_os=HostOS.LINUX,
        )
    )
    FindingRepository(database).create(
        FindingCreate(
            analysis_run_id=run.id,
            rule_id="TEST-RULE",
            title="Recorded test finding",
            description="Stored finding description",
            severity=FindingSeverity.HIGH,
            confidence=0.8,
        )
    )

    page = FindingsPage()
    qtbot.addWidget(page)
    page.open_case(str(tmp_path), case)

    assert "1 recorded finding" in page.status.text()
    assert page.findings_layout.count() == 1
    card = page.findings_layout.itemAt(0).widget()
    assert card is not None
    labels = card.findChildren(QLabel)
    assert any("Recorded test finding" in item.text() for item in labels)
    assert any("TEST-RULE" in item.text() for item in labels)


def test_findings_page_empty_state_is_real(qtbot, tmp_path):
    _, case, _ = create_workspace_case(tmp_path)
    page = FindingsPage()
    qtbot.addWidget(page)
    page.open_case(str(tmp_path), case)

    assert page.status.text() == "No findings recorded for this case."
    assert page.findings_layout.count() == 0


def test_main_window_findings_integration(qtbot, tmp_path):
    from memsentry.gui.main_window import MainWindow

    _database, case, _evidence = create_workspace_case(tmp_path)
    window = MainWindow()
    qtbot.addWidget(window)

    window._open_case(str(tmp_path), case)
    assert window.findings_page.case == case
    assert window.findings_page.status.text() == "No findings recorded for this case."

    # Switch sidebar to Findings (index 4 in PAGE_NAMES)
    window.sidebar.setCurrentRow(4)
    preview = window.findChild(QLabel, "previewBanner")
    assert preview is not None
    assert not preview.isVisible()

