"""Tests for TimelineView component."""

from __future__ import annotations

from typing import Any

from memsentry.gui.timeline_view import TimelineView


def test_timeline_view_initialization(qtbot: Any) -> None:
    view = TimelineView()
    qtbot.addWidget(view)

    assert len(view.cards_map) == 7
    assert view.selected_event["id"] == "EVT-004"
    assert view.detail_title_lbl.text() == "powershell.exe (PID 9248) spawned by WINWORD.EXE"
    assert view.kv_artifact.text() == "PID:9248"


def test_timeline_view_card_click_updates_details(qtbot: Any) -> None:
    view = TimelineView()
    qtbot.addWidget(view)

    view._on_event_clicked("EVT-005")

    assert view.selected_event["id"] == "EVT-005"
    assert view.detail_title_lbl.text() == "powershell.exe connected to 185.220.101.47:443"
    assert view.kv_artifact.text() == "185.220.101.47:443"


def test_timeline_view_signals(qtbot: Any) -> None:
    view = TimelineView()
    qtbot.addWidget(view)

    with qtbot.waitSignal(view.open_relationship_graph_requested, timeout=1000):
        view.open_relationship_graph_requested.emit()

    with qtbot.waitSignal(view.open_evidence_explorer_requested, timeout=1000):
        view.open_evidence_explorer_requested.emit()
