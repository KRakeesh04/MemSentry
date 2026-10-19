from types import SimpleNamespace
from uuid import uuid4

from PySide6.QtCore import QPoint, Qt
from PySide6.QtGui import QFontMetrics

from memsentry.gui.analysis_dialog import AnalysisDialog, AnalysisWorker
from memsentry.volatility.plugin_registry import PluginRegistry


def test_picker_requires_os_and_selection(qtbot, tmp_path, monkeypatch):
    registry = PluginRegistry(discovered_plugins={"windows.pslist.PsList": object})
    monkeypatch.setattr("memsentry.gui.analysis_dialog.PluginRegistry", lambda: registry)
    evidence = SimpleNamespace(id=uuid4(), evidence_os=None, original_filename="test.mem")
    dialog = AnalysisDialog(str(tmp_path), evidence)
    qtbot.addWidget(dialog)
    qtbot.waitUntil(lambda: not dialog.catalog.isRunning() and dialog.registry is not None)
    assert dialog.plugins.count() == 0
    dialog.os_choice.setCurrentIndex(1)
    assert dialog.plugins.count() == 1
    check = dialog.plugin_checks["process_list"]
    check.setChecked(False)
    dialog._accept()
    assert "Select at least one" in dialog.message.text()
    check.setChecked(True)
    (tmp_path / "symbols" / "windows").mkdir(parents=True)
    dialog.yara.setChecked(False)
    dialog._accept()
    assert dialog.request.plugin_ids == ("process_list",)
    assert dialog.request.yara_rules == ()
    assert dialog.request.os_type == "windows"


def test_plugin_row_and_checkbox_toggle_once_and_support_keyboard(qtbot, tmp_path, monkeypatch):
    registry = PluginRegistry(discovered_plugins={"windows.pslist.PsList": object})
    monkeypatch.setattr("memsentry.gui.analysis_dialog.PluginRegistry", lambda: registry)
    evidence = SimpleNamespace(id=uuid4(), evidence_os="windows", original_filename="test.mem")
    dialog = AnalysisDialog(str(tmp_path), evidence)
    qtbot.addWidget(dialog)
    qtbot.waitUntil(lambda: not dialog.catalog.isRunning() and dialog.registry is not None)
    dialog.show()
    item = dialog.plugins.item(0)
    check = dialog.plugin_checks["process_list"]
    qtbot.waitUntil(lambda: check.isVisible() and check.width() > 0)
    assert item.text() == ""
    assert " - " in check.text()
    assert "—" not in check.text()
    assert item.sizeHint().height() >= check.sizeHint().height()
    initial = check.isChecked()
    text_width = QFontMetrics(check.font()).horizontalAdvance(check.text())
    label_point = QPoint(min(check.width() - 2, text_width // 2 + 24), check.height() // 2)
    qtbot.mouseClick(check, Qt.MouseButton.LeftButton, pos=label_point)
    assert check.isChecked() != initial
    qtbot.mouseClick(check, Qt.MouseButton.LeftButton, pos=label_point)
    assert check.isChecked() == initial
    check.setFocus()
    qtbot.keyClick(check, Qt.Key.Key_Space)
    assert check.isChecked() != initial
    check.setEnabled(False)
    qtbot.mouseClick(check, Qt.MouseButton.LeftButton, pos=label_point)
    assert check.isChecked() != initial


def test_yara_display_is_short_but_request_keeps_full_paths(qtbot, tmp_path, monkeypatch):
    registry = PluginRegistry(discovered_plugins={"windows.pslist.PsList": object})
    monkeypatch.setattr("memsentry.gui.analysis_dialog.PluginRegistry", lambda: registry)
    evidence = SimpleNamespace(id=uuid4(), evidence_os="windows", original_filename="test.mem")
    dialog = AnalysisDialog(str(tmp_path), evidence)
    qtbot.addWidget(dialog)
    qtbot.waitUntil(lambda: not dialog.catalog.isRunning() and dialog.registry is not None)
    rule = tmp_path / "custom.yara"
    monkeypatch.setattr(
        "memsentry.gui.analysis_dialog.QFileDialog.getOpenFileNames",
        lambda *_: ([str(rule)], ""),
    )
    dialog._rules()
    assert dialog.rules.text() == "custom.yara"
    assert dialog.rules.toolTip() == str(rule)
    dialog._accept()
    assert dialog.request.yara_rules == (rule,)


def test_worker_routes_success_and_failure(qtbot, monkeypatch):
    monkeypatch.setattr(
        "memsentry.gui.analysis_dialog.run_analysis", lambda request, started: "done"
    )
    worker = AnalysisWorker(object())
    with qtbot.waitSignal(worker.succeeded) as result:
        worker.start()
    worker.wait()
    assert result.args == ["done"]

    def fail(*args):
        raise ValueError("Missing symbols")

    monkeypatch.setattr("memsentry.gui.analysis_dialog.run_analysis", fail)
    with qtbot.waitSignal(worker.failed) as error:
        worker.start()
    worker.wait()
    assert error.args == ["Missing symbols"]


def test_main_window_keeps_job_alive_and_blocks_close(qtbot, tmp_path, monkeypatch):
    from threading import Event

    from PySide6.QtCore import QSettings
    from PySide6.QtWidgets import QDialog

    from memsentry.app.analysis_job import AnalysisRequest
    from memsentry.app.intake_service import IntakeRequest, IntakeService
    from memsentry.gui.main_window import MainWindow

    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)
    for module in ("cases", "evidence"):
        monkeypatch.setattr(f"memsentry.gui.pages.{module}.QSettings", lambda *_: settings)
    source = tmp_path / "synthetic.mem"
    source.write_bytes(b"synthetic test evidence")
    result = IntakeService().run(
        IntakeRequest(tmp_path, "TEST", "Test", source), lambda *_: None, Event()
    )
    window = MainWindow()
    qtbot.addWidget(window)
    window._evidence_registered(result)
    request = AnalysisRequest(
        str(tmp_path), result.evidence.id, "windows", ("process_list",), tmp_path
    )
    monkeypatch.setattr(
        "memsentry.gui.main_window.AnalysisDialog",
        lambda *args: SimpleNamespace(
            exec=lambda: QDialog.DialogCode.Accepted, request=request, deleteLater=lambda: None
        ),
    )
    release = Event()

    def analyze(*args):
        if not release.wait(5):
            raise RuntimeError("Test release timed out")
        return SimpleNamespace(id=uuid4(), status="completed", error_message=None)

    monkeypatch.setattr("memsentry.gui.analysis_dialog.run_analysis", analyze)
    monkeypatch.setattr("memsentry.gui.main_window.QMessageBox.information", lambda *args: None)
    window.show()
    try:
        assert window.minimumWidth() == 1100
        assert window.minimumHeight() == 720
        assert "MEM" in window.sidebar.brand.wordmark.text()
        assert "SENTRY" in window.sidebar.brand.wordmark.text()
        assert window.sidebar.brand.wordmark.font().pointSize() == 12
        window.resize(window.minimumWidth(), window.height())
        assert window.sidebar.brand.wordmark.font().pointSize() == 12
        window.resize(1200, window.height())
        assert window.sidebar.brand.wordmark.font().pointSize() == 16
        window._start_analysis()
        assert window.analysis_worker is not None
        assert not window.running_banner.isHidden()
        assert "Test · TEST" in window.running_case_label.text()
        window.sidebar.setCurrentRow(0)
        assert not window.running_banner.isHidden()
        window.running_case_button.click()
        assert window.pages.currentIndex() == 1
        assert window.overview_page.evidence_choice.currentData().id == result.evidence.id
        assert not window.evidence_page.start.isEnabled()
        assert not window.close()
    finally:
        release.set()
        qtbot.waitUntil(lambda: window.analysis_worker is None)
    assert window.evidence_page.start.isEnabled()
    assert window.running_banner.isHidden()
    assert "completed" in window.job_status.text()
