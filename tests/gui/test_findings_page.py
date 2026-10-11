from __future__ import annotations

from threading import Event

import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QLabel, QMessageBox, QPushButton

from memsentry.app.case_service import workspace_database
from memsentry.app.intake_service import IntakeRequest, IntakeService
from memsentry.gui.pages.findings import FindingsPage
from memsentry.gui.theme import workspace_stylesheet
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

    assert page.status.text() == "1 of 1 finding(s) shown."
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


@pytest.mark.parametrize("background", ["#11151C", "#F1F5F9"])
def test_cards_reflow_without_clipping_and_keep_filters(qtbot, qapp, tmp_path, monkeypatch, background):
    database, case, evidence = create_workspace_case(tmp_path)
    run = AnalysisRunRepository(database).create(AnalysisRunCreate(
        evidence_id=evidence.id, application_version="test", volatility_version="test",
        host_os=HostOS.LINUX))
    for index in range(9):
        FindingRepository(database).create(FindingCreate(
            analysis_run_id=run.id, rule_id=f"TEST-{index:03}",
            title="Suspicious parent-child relationship" if index % 2 else "Executable private memory",
            description=("A configurable parent-child process relationship matches a suspicious pair. "
                         f"Process: example-{index}.exe (PID: {1000 + index}). "
                         "Review the command line and supporting artifacts before drawing conclusions."),
            severity=FindingSeverity.MEDIUM, confidence=.5))
    original_palette = qapp.palette()
    palette = QPalette(original_palette)
    palette.setColor(QPalette.ColorRole.Window, QColor(background))
    qapp.setPalette(palette)
    try:
        page = FindingsPage()
        qtbot.addWidget(page)
        page.setObjectName("workspace")
        page.setStyleSheet(workspace_stylesheet())
        page.open_case(str(tmp_path), case)
        page.show()
        for width, columns in ((1680, 3), (1100, 2), (700, 1), (1680, 3)):
            page.resize(width, 950)
            qtbot.waitUntil(lambda count=columns:
                            page.findings_layout.getItemPosition(2)[1] == 2 % count)
            qtbot.wait(30)
            assert page.horizontalScrollBar().maximum() == 0
            for card in page._cards:
                for label in card.findChildren(QLabel):
                    if label.wordWrap():
                        assert label.height() >= label.heightForWidth(label.width())
            assert not any(button.text() == "Explore relationships"
                           for button in page.findChildren(QPushButton))
            page.grab().save(str(tmp_path / f"findings-{width}.png"))
        page.search.setText("example-3.exe")
        assert page.findings_layout.count() == 1
        assert page.status.text() == "1 of 9 finding(s) shown."
        page.severity_filter.setCurrentText("High")
        assert page.findings_layout.count() == 0
        assert page.empty_state.isVisible()
        page.severity_filter.setCurrentText("All severities")
        monkeypatch.setattr(QMessageBox, "exec", lambda _: 0)
        card = page._cards[0]
        card.setFocus()
        with qtbot.waitSignal(card.clicked):
            qtbot.keyClick(card, Qt.Key.Key_Return)
    finally:
        qapp.setPalette(original_palette)


# def test_main_window_findings_integration(qtbot, tmp_path):
#     from memsentry.gui.main_window import MainWindow

#     _database, case, _evidence = create_workspace_case(tmp_path)
#     window = MainWindow()
#     qtbot.addWidget(window)

#     window._open_case(str(tmp_path), case)
#     assert window.findings_page.case == case
#     assert window.findings_page.status.text() == "No findings recorded for this case."

#     # Switch sidebar to Findings (index 4 in PAGE_NAMES)
#     window.sidebar.setCurrentRow(4)
#     preview = window.findChild(QLabel, "previewBanner")
#     assert preview is not None
#     assert not preview.isVisible()
