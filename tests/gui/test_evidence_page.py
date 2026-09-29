from PySide6.QtCore import QSettings

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
