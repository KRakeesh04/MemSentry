from threading import Event
from unittest.mock import Mock

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QDialog

from memsentry.app.intake_service import IntakeRequest, IntakeService
from memsentry.gui.main_window import MainWindow
from memsentry.gui.pages.evidence import EvidencePage


def test_import_worker_updates_ui_and_database(qtbot, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "memsentry.gui.pages.evidence.QSettings",
        lambda *_: QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat),
    )
    page = EvidencePage()
    qtbot.addWidget(page)
    source = tmp_path / "fixture.mem"
    source.write_bytes(b"synthetic test image")
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    page.workspace.setText(str(workspace))
    page.case_number.setText("TEST")
    page.case_name.setText("UI test")
    page.source.setText(str(source))
    with qtbot.waitSignal(page.evidence_registered, timeout=5000):
        page.start.click()
    qtbot.waitUntil(lambda: page.worker is None)
    assert "verified and registered" in page.result.toPlainText()
    assert page.progress.value() == 100
    assert page.start.isEnabled()
    assert not page.analyse.isHidden()
    assert page.analyse.isEnabled()
    assert (workspace / "memsentry.sqlite3").is_file()


def test_live_mode_requires_authorization(qtbot):
    page = EvidencePage()
    qtbot.addWidget(page)
    page.mode.setCurrentIndex(1)
    page.workspace.setText("/unused")
    page.case_number.setText("TEST")
    page.case_name.setText("Test")
    page.start.click()
    assert page.worker is None
    assert "authorization" in page.result.toPlainText()


def test_navigation_retains_live_page_and_distinguishes_previews(qtbot):
    window = MainWindow()
    qtbot.addWidget(window)
    for index in range(len(window.PAGE_NAMES)):
        window.sidebar.setCurrentRow(index)
        assert window.pages.currentIndex() == index
    window.sidebar.setCurrentRow(2)
    assert window.pages.currentWidget() is window.evidence_page


def test_analyse_intake_redirects_and_uses_overview_dialog(qtbot, tmp_path, monkeypatch):
    monkeypatch.setattr(
        "memsentry.gui.pages.evidence.QSettings",
        lambda *_: QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat),
    )
    source = tmp_path / "fixture.mem"
    source.write_bytes(b"synthetic test image")
    request = IntakeRequest(tmp_path / "workspace", "TEST", "UI test", source=source)
    request.workspace.mkdir()
    first = IntakeService().run(request, lambda *_: None, Event())
    second = IntakeService().run(request, lambda *_: None, Event())
    window = MainWindow()
    qtbot.addWidget(window)
    window.evidence_page._succeeded(second)
    choice = window.overview_page.evidence_choice
    for index in range(choice.count()):
        if choice.itemData(index).id == first.evidence.id:
            choice.setCurrentIndex(index)
            break
    calls = []

    def dialog(workspace, evidence, parent):
        assert window.pages.currentWidget() is window.overview_page
        assert evidence.id == second.evidence.id
        assert workspace == str(second.database_path.parent)
        calls.append(evidence.id)
        return Mock(exec=Mock(return_value=QDialog.DialogCode.Rejected))

    monkeypatch.setattr("memsentry.gui.main_window.AnalysisDialog", dialog)
    for _ in range(2):
        window.sidebar.setCurrentRow(2)
        window.evidence_page.analyse.click()
        assert window.pages.currentWidget() is window.overview_page
        assert window.evidence_page.analyse.isEnabled()
        assert window.analysis_worker is None
    assert calls == [second.evidence.id, second.evidence.id]
