from types import SimpleNamespace

import pytest
from PySide6.QtGui import QColor, QPalette
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QVBoxLayout, QWidget

from memsentry.gui.theme import workspace_stylesheet
from memsentry.gui.workflow_stepper import ASSETS, WorkflowStepper


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


@pytest.mark.parametrize("dark", [False, True])
def test_workflow_rail_layout(qtbot, qapp, tmp_path, dark):
    old = qapp.palette()
    palette = QPalette(old)
    palette.setColor(QPalette.ColorRole.Window, QColor("#11151C" if dark else "#F1F5F9"))
    qapp.setPalette(palette)
    try:
        host = QWidget()
        host.setMinimumSize(0, 0)
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
        assert widget.summary.text() == "4 of 8 complete"
        assert all("SHA-256" not in gate.text() for gate in widget.gates)
        for index, (icon, _) in enumerate(widget.nodes):
            image = icon.pixmap().toImage()
            colors = {
                image.pixelColor(x, y).name()
                for x in range(image.width())
                for y in range(image.height())
                if image.pixelColor(x, y).alpha() > 200
            }
            assert colors
            blue = "#60a5fa" if dark else "#2563eb"
            assert (blue in colors) == (index < 4)
        assert "Expected:" in widget.gates[2].toolTip()
        host.grab().save(str(tmp_path / "workflow.png"))
        host.resize(520, 240)
        # Process the resize with the host unconstrained by its layout size hint.
        qtbot.waitUntil(
            lambda: host.width() == 520
            and widget.rail_scroll.horizontalScrollBar().maximum() > 0,
            timeout=5000,
        )
        assert widget.rail_scroll.horizontalScrollBar().maximum() > 0
        assert widget.rail_scroll.verticalScrollBar().maximum() == 0
        host.grab().save(str(tmp_path / "workflow-narrow.png"))
    finally:
        qapp.setPalette(old)


@pytest.mark.parametrize("initial_background", ["#11151C", "#F1F5F9"])
def test_workflow_icons_follow_palette_changes(qtbot, qapp, initial_background):
    old = qapp.palette()
    try:
        initial = QPalette(old)
        initial.setColor(QPalette.ColorRole.Window, QColor(initial_background))
        qapp.setPalette(initial)
        widget = WorkflowStepper()
        qtbot.addWidget(widget)
        widget.show_records(
            object(),
            None,
            None,
            [event("evidence", "operation", "running"), event("verify", "operation", "failed")],
        )
        for background, blue in (("#11151C", "#60A5FA"), ("#F1F5F9", "#2563EB")):
            palette = QPalette(old)
            palette.setColor(QPalette.ColorRole.Window, QColor(background))
            qapp.setPalette(palette)
            assert blue in widget.nodes[0][1].styleSheet()
            for icon, caption in widget.nodes[1:]:
                assert blue not in icon.styleSheet()
                assert blue not in caption.styleSheet()
            assert widget.status_labels[1].text() == "In progress"
            assert widget.status_labels[2].text() == "Failed"
    finally:
        qapp.setPalette(old)


def test_workflow_svg_assets_are_valid():
    for name in (
        "case",
        "evidence",
        "verify",
        "analyze",
        "investigate",
        "correlate",
        "findings",
        "report",
        "verified_badge",
    ):
        assert QSvgRenderer(str(ASSETS / f"{name}.svg")).isValid()
