"""Tests for RelationshipGraphView component."""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import QPointF, Qt
from PySide6.QtWidgets import QApplication

from memsentry.gui.graph_view import GRAPH_NODES, RelationshipGraphView


def test_graph_view_initialization(qtbot: Any) -> None:
    view = RelationshipGraphView()
    qtbot.addWidget(view)

    assert view.objectName() == "RelationshipGraphView"
    assert view.node_title_lbl.text() == "powershell.exe"
    assert view.node_pid_lbl.text() == "PID 9248"
    assert "Relationships" in view.rel_header_lbl.text()


def test_graph_view_node_selection_updates_inspector(qtbot: Any) -> None:
    view = RelationshipGraphView()
    qtbot.addWidget(view)

    view._on_node_selected("winword")

    assert view.node_title_lbl.text() == "WINWORD.EXE"
    assert view.node_pid_lbl.text() == "PID 8192"
    assert "Relationships (3)" in view.rel_header_lbl.text()


def test_graph_view_signals(qtbot: Any) -> None:
    view = RelationshipGraphView()
    qtbot.addWidget(view)

    with qtbot.waitSignal(view.back_to_investigation_requested, timeout=1000):
        view._on_view_in_process_tree()

    with qtbot.waitSignal(view.show_in_timeline_requested, timeout=1000):
        view.show_in_timeline_requested.emit()

    with qtbot.waitSignal(view.check_findings_requested, timeout=1000):
        view.check_findings_requested.emit()
