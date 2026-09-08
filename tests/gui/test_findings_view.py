"""Tests for FindingsView component."""

from __future__ import annotations

from typing import Any

from memsentry.gui.findings_view import SAMPLE_FINDINGS, FindingsView


def test_findings_view_initialization(qtbot: Any) -> None:
    view = FindingsView()
    qtbot.addWidget(view)

    assert len(view.cards_map) == 5
    assert view.selected_finding["id"] == "FND-001"
    assert view.detail_title_lbl.text() == "Malicious Office Macro — PowerShell Execution"
    assert view.confidence_bar.value() == 94


def test_findings_view_card_click_updates_details(qtbot: Any) -> None:
    view = FindingsView()
    qtbot.addWidget(view)

    view._on_card_clicked("FND-002")

    assert view.selected_finding["id"] == "FND-002"
    assert view.detail_title_lbl.text() == "C2 Beacon — TOR Exit Node (Cobalt Strike)"
    assert view.confidence_bar.value() == 91
    assert view.detail_mitre_badge.text() == "T1071.001"


def test_findings_view_signals(qtbot: Any) -> None:
    view = FindingsView()
    qtbot.addWidget(view)

    with qtbot.waitSignal(view.open_relationship_graph_requested, timeout=1000):
        view.open_relationship_graph_requested.emit()

    with qtbot.waitSignal(view.open_evidence_explorer_requested, timeout=1000):
        view.open_evidence_explorer_requested.emit()
