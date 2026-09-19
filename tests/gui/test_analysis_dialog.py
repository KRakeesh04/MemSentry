from types import SimpleNamespace
from uuid import uuid4

from PySide6.QtCore import Qt

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
    item = dialog.plugins.item(0)
    item.setCheckState(Qt.CheckState.Unchecked)
    dialog._accept()
    assert "Select at least one" in dialog.message.text()
    item.setCheckState(Qt.CheckState.Checked)
    (tmp_path / "symbols" / "windows").mkdir(parents=True)
    dialog.yara.setChecked(False)
    dialog._accept()
    assert dialog.request.plugin_ids == ("process_list",)
    assert dialog.request.yara_rules == ()
    assert dialog.request.os_type == "windows"


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
        window._start_analysis()
        assert window.analysis_worker is not None
        assert not window.evidence_page.start.isEnabled()
        assert not window.close()
    finally:
        release.set()
        qtbot.waitUntil(lambda: window.analysis_worker is None)
    assert window.evidence_page.start.isEnabled()
    assert "completed" in window.job_status.text()
