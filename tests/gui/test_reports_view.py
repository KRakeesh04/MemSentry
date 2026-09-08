"""Tests for ReportBuilderView component."""

from __future__ import annotations

from typing import Any

from memsentry.gui.reports_view import ReportBuilderView


def test_reports_view_initialization(qtbot: Any) -> None:
    view = ReportBuilderView()
    qtbot.addWidget(view)

    assert view.objectName() == "ReportBuilderView"
    assert view.title_input.text() == "Forensic Analysis Report — CORP-2024-0187"
    assert view.investigator_input.text() == "J. Mercer"
    assert view.classification_combo.currentText() == "RESTRICTED"
    assert view.prev_title_lbl.text() == "Forensic Analysis Report — CORP-2024-0187"


def test_reports_view_title_update(qtbot: Any) -> None:
    view = ReportBuilderView()
    qtbot.addWidget(view)

    view.title_input.setText("Custom Incident Report")

    assert view.prev_title_lbl.text() == "Custom Incident Report"


def test_reports_view_format_selection(qtbot: Any) -> None:
    view = ReportBuilderView()
    qtbot.addWidget(view)

    view._select_format("DOCX")
    assert view.format_combo.currentText() == "DOCX"

    view._select_format("PDF")
    assert view.format_combo.currentText() == "PDF"
