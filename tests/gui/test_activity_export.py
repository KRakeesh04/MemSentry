import json
from types import SimpleNamespace

from PySide6.QtCore import Qt

from memsentry.gui.pages.activity import ActivityPage


def test_exports_only_filtered_events_in_table_order(qtbot, tmp_path, monkeypatch):
    page = ActivityPage()
    qtbot.addWidget(page)
    page.case = SimpleNamespace(id="case-1", case_number="CASE-1")
    base = {"evidence_id": "e1", "analysis_run_id": "r1", "stage": "verify", "phase": "after",
            "status": "failed", "expected_sha256": "abc", "actual_sha256": "def", "progress": 100}
    page.all_events = [dict(base, id=i, created_at=f"2026-10-15T00:00:0{i}+00:00",
                            message="Hash mismatch\nDetails: λ") for i in range(1, 4)]
    page.all_events += [dict(base, id=4, evidence_id="e2", message="Hash mismatch"),
                        dict(base, id=5, analysis_run_id="r2", message="Hash mismatch"),
                        dict(base, id=6, status="completed", message="Hash mismatch"),
                        dict(base, id=7, actual_sha256="abc", message="Hash mismatch"),
                        dict(base, id=8, message="Different failure")]
    page.evidence_combo.addItem("Evidence 1", SimpleNamespace(id="e1"))
    page.evidence_combo.setCurrentIndex(1)
    page.run_combo.addItem("Run 1", SimpleNamespace(id="r1"))
    page.run_combo.setCurrentIndex(1)
    page.status_combo.setCurrentText("Failed")
    page.integrity_combo.setCurrentText("Mismatch")
    page.search_input.setText("Hash mismatch")
    page.table.sortItems(0, Qt.SortOrder.AscendingOrder)
    monkeypatch.setattr("memsentry.gui.pages.activity.QFileDialog.getSaveFileName",
                        lambda *args: (str(tmp_path / "filtered"), ""))
    page.export_button.click()
    lines = (tmp_path / "filtered.log").read_text(encoding="utf-8").splitlines()
    header = json.loads(lines[1][2:])
    assert header["event_count"] == 3
    assert header["filters"]["status"] == "Failed"
    assert header["case_id"] == "case-1"
    exported = [json.loads(line) for line in lines[2:]]
    assert exported == page.all_events[:3]
    assert "Exported 3" in page.message.text()
    page.search_input.setText("no matching event")
    assert not page.export_button.isEnabled()


def test_export_cancel_and_existing_file_are_safe(qtbot, tmp_path, monkeypatch):
    page = ActivityPage()
    qtbot.addWidget(page)
    page.all_events = [{"id": 1, "message": "synthetic event"}]
    page._filter_events()
    monkeypatch.setattr("memsentry.gui.pages.activity.QFileDialog.getSaveFileName",
                        lambda *args: ("", ""))
    page.export_button.click()
    assert not list(tmp_path.iterdir())
    target = tmp_path / "existing.log"
    target.write_text("preserve original")
    monkeypatch.setattr("memsentry.gui.pages.activity.QFileDialog.getSaveFileName",
                        lambda *args: (str(target), ""))
    page.export_button.click()
    assert target.read_text() == "preserve original"
    assert "already exists" in page.message.text()
    monkeypatch.setattr("memsentry.gui.pages.activity.QFileDialog.getSaveFileName",
                        lambda *args: (str(tmp_path / "missing" / "export.log"), ""))
    page.export_button.click()
    assert "Could not export logs" in page.message.text()
