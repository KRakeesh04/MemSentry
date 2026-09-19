from types import SimpleNamespace

from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QVBoxLayout, QWidget

from memsentry.gui.theme import workspace_stylesheet
from memsentry.gui.workflow_stepper import WorkflowStepper


def event(stage, phase, status):
    return {"stage": stage, "phase": phase, "status": status, "progress": 100, "message": "test"}


def test_stepper_does_not_invent_verification(qtbot):
    widget = WorkflowStepper()
    qtbot.addWidget(widget)
    widget.show_records(
        object(),
        SimpleNamespace(integrity_status="verified"),
        SimpleNamespace(status="completed"),
        [],
    )
    assert widget.states[3] == "untracked"
    assert widget.checkpoints[0] == "na"
    assert "completed" not in widget.checkpoints[1:]


def test_stepper_shows_progress_and_blocks_after_failure(qtbot):
    widget = WorkflowStepper()
    qtbot.addWidget(widget)
    evidence = SimpleNamespace(integrity_status="verified")
    events = [event("verify", "operation", "completed"), event("analyze", "before", "running")]
    widget.show_records(object(), evidence, None, events)
    assert widget.states[3] == "running"
    assert widget.checkpoints[2] == "running"
    events.append(event("analyze", "before", "failed"))
    widget.show_records(object(), evidence, None, events)
    assert widget.states[3] == "failed"
    assert widget.states[4:] == ["pending"] * 4
    assert widget.checkpoints[2] == "failed"


def test_workflow_rail_layout(qtbot, qapp, tmp_path):
    old = qapp.palette()
    palette = QPalette(old)
    palette.setColor(QPalette.ColorRole.Window, QColor("#11151C"))
    qapp.setPalette(palette)
    try:
        host = QWidget()
        qtbot.addWidget(host)
        host.setObjectName("workspace")
        layout = QVBoxLayout(host)
        widget = WorkflowStepper()
        layout.addWidget(widget)
        events = [
            event("verify", "operation", "completed"),
            event("evidence", "after", "completed"),
            event("analyze", "before", "completed"),
            event("analyze", "after", "completed"),
            event("analyze", "operation", "completed"),
        ]
        widget.show_records(object(), SimpleNamespace(integrity_status="verified"), None, events)
        host.setStyleSheet(workspace_stylesheet())
        host.resize(1450, 205)
        host.show()
        qtbot.waitUntil(host.isVisible)
        qtbot.wait(50)
        assert widget.states[:4] == ["completed"] * 4
        assert widget.states[4] == "ready"
        host.grab().save(str(tmp_path / "workflow.png"))
    finally:
        qapp.setPalette(old)
