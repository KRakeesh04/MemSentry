from __future__ import annotations

import json
from hashlib import sha256
from pathlib import Path

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QMessageBox

from memsentry.gui.pages.reports import ReportsPage
from memsentry.models.case import CaseCreate
from memsentry.models.evidence import EvidenceCreate
from memsentry.storage.database import Database
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.workflow_repository import WorkflowRepository


def _create_test_case(tmp_path: Path):
    db_path = tmp_path / "memsentry.sqlite3"
    db = Database(db_path)
    db.initialize()

    case_repo = CaseRepository(db)
    evidence_repo = EvidenceRepository(db)

    case = case_repo.create(CaseCreate(case_number="CASE-999", name="Test Reporting Case"))
    source = tmp_path / "test.mem"
    source.write_bytes(b"sample memory image bytes")
    evidence = evidence_repo.create(
        EvidenceCreate(
            case_id=case.id,
            original_filename=source.name,
            file_path=source,
            file_size_bytes=source.stat().st_size,
            sha256=sha256(source.read_bytes()).hexdigest(),
        )
    )
    WorkflowRepository(db).record(
        evidence_id=evidence.id,
        run_id=None,
        stage="case",
        phase="operation",
        status="completed",
        message="Created case evidence",
    )
    return db, case


def test_reports_page_defaults_from_settings(qtbot, tmp_path, monkeypatch):
    settings_file = str(tmp_path / "test_settings.ini")
    ini = QSettings(settings_file, QSettings.Format.IniFormat)
    ini.setValue("reporting/format", "both")
    out_dir = str(tmp_path / "configured_reports")
    ini.setValue("reporting/output_directory", out_dir)

    monkeypatch.setattr(
        "memsentry.gui.pages.reports.QSettings",
        lambda *_: QSettings(settings_file, QSettings.Format.IniFormat),
    )

    page = ReportsPage()
    qtbot.addWidget(page)

    assert page.both_radio.isChecked()
    assert not page.html_radio.isChecked()
    assert not page.json_radio.isChecked()
    assert page.output_dir_input.text() == out_dir


def test_reports_page_generate_both_reports_without_prompt(qtbot, tmp_path, monkeypatch):
    _db, case = _create_test_case(tmp_path)
    out_dir = tmp_path / "generated_reports"

    settings_file = str(tmp_path / "test_settings.ini")
    ini = QSettings(settings_file, QSettings.Format.IniFormat)
    ini.setValue("reporting/format", "both")
    ini.setValue("reporting/output_directory", str(out_dir))

    monkeypatch.setattr(
        "memsentry.gui.pages.reports.QSettings",
        lambda *_: QSettings(settings_file, QSettings.Format.IniFormat),
    )
    monkeypatch.setattr(QMessageBox, "information", lambda *_: QMessageBox.StandardButton.Ok)

    page = ReportsPage()
    qtbot.addWidget(page)
    page.open_case(str(tmp_path), case)

    assert page.btn_generate.isEnabled()
    assert page.both_radio.isChecked()
    assert page.output_dir_input.text() == str(out_dir)

    # Click generate report - should not pop up file dialog, directly writes to out_dir
    page.btn_generate.click()

    html_file = out_dir / "MemSentry-Report-CASE-999.html"
    json_file = out_dir / "MemSentry-Report-CASE-999.json"

    assert html_file.exists()
    assert json_file.exists()

    html_content = html_file.read_text(encoding="utf-8")
    assert "CASE-999" in html_content

    json_content = json.loads(json_file.read_text(encoding="utf-8"))
    assert json_content["case"]["case_number"] == "CASE-999"


def test_reports_page_generate_single_format(qtbot, tmp_path, monkeypatch):
    _db, case = _create_test_case(tmp_path)
    out_dir = tmp_path / "json_reports"

    settings_file = str(tmp_path / "test_settings.ini")
    ini = QSettings(settings_file, QSettings.Format.IniFormat)
    ini.setValue("reporting/format", "json")
    ini.setValue("reporting/output_directory", str(out_dir))

    monkeypatch.setattr(
        "memsentry.gui.pages.reports.QSettings",
        lambda *_: QSettings(settings_file, QSettings.Format.IniFormat),
    )
    monkeypatch.setattr(QMessageBox, "information", lambda *_: QMessageBox.StandardButton.Ok)

    page = ReportsPage()
    qtbot.addWidget(page)
    page.open_case(str(tmp_path), case)

    assert page.json_radio.isChecked()
    page.btn_generate.click()

    json_file = out_dir / "MemSentry-Report-CASE-999.json"
    html_file = out_dir / "MemSentry-Report-CASE-999.html"

    assert json_file.exists()
    assert not html_file.exists()
    # Unsigned by default in this test setup
    assert not (out_dir / "MemSentry-Report-CASE-999.json.sig.json").exists()


def test_reports_page_generate_with_digital_signing(qtbot, tmp_path, monkeypatch):
    _db, case = _create_test_case(tmp_path)
    out_dir = tmp_path / "signed_reports"
    keys_dir = tmp_path / "app_keys"

    settings_file = str(tmp_path / "test_settings.ini")
    ini = QSettings(settings_file, QSettings.Format.IniFormat)
    ini.setValue("reporting/format", "both")
    ini.setValue("reporting/output_directory", str(out_dir))
    ini.setValue("reporting/sign_reports", "true")

    monkeypatch.setattr(
        "memsentry.gui.pages.reports.QSettings",
        lambda *_: QSettings(settings_file, QSettings.Format.IniFormat),
    )
    monkeypatch.setattr(QMessageBox, "information", lambda *_: QMessageBox.StandardButton.Ok)

    # Point ReportSigningService default key dir to keys_dir
    from memsentry.reports import signer
    orig_init = signer.ReportSigningService.__init__
    monkeypatch.setattr(
        signer.ReportSigningService,
        "__init__",
        lambda self, key_dir=None: orig_init(self, key_dir=key_dir or keys_dir),
    )

    page = ReportsPage()
    qtbot.addWidget(page)
    page.open_case(str(tmp_path), case)

    assert page.chk_sign.isChecked()
    page.btn_generate.click()

    html_file = out_dir / "MemSentry-Report-CASE-999.html"
    json_file = out_dir / "MemSentry-Report-CASE-999.json"
    html_sig = out_dir / "MemSentry-Report-CASE-999.html.sig.json"
    json_sig = out_dir / "MemSentry-Report-CASE-999.json.sig.json"

    assert html_file.exists()
    assert json_file.exists()
    assert html_sig.exists()
    assert json_sig.exists()


def test_reports_page_verify_action(qtbot, tmp_path, monkeypatch):
    from PySide6.QtWidgets import QFileDialog

    _db, case = _create_test_case(tmp_path)
    out_dir = tmp_path / "verified_reports"
    keys_dir = tmp_path / "app_keys"

    # Export a signed report first
    from memsentry.reports import signer
    orig_init = signer.ReportSigningService.__init__
    monkeypatch.setattr(
        signer.ReportSigningService,
        "__init__",
        lambda self, key_dir=None: orig_init(self, key_dir=key_dir or keys_dir),
    )

    settings_file = str(tmp_path / "test_settings.ini")
    ini = QSettings(settings_file, QSettings.Format.IniFormat)
    ini.setValue("reporting/format", "html")
    ini.setValue("reporting/output_directory", str(out_dir))
    ini.setValue("reporting/sign_reports", "true")

    monkeypatch.setattr(
        "memsentry.gui.pages.reports.QSettings",
        lambda *_: QSettings(settings_file, QSettings.Format.IniFormat),
    )
    monkeypatch.setattr(QMessageBox, "information", lambda *_: QMessageBox.StandardButton.Ok)

    page = ReportsPage()
    qtbot.addWidget(page)
    page.open_case(str(tmp_path), case)
    page.btn_generate.click()

    html_file = out_dir / "MemSentry-Report-CASE-999.html"
    assert html_file.exists()

    # Verify action mock
    monkeypatch.setattr(QFileDialog, "getOpenFileName", lambda *args, **kwargs: (str(html_file), "HTML"))

    dialog_captured = []
    from memsentry.gui.details_dialog import DetailsDialog
    orig_exec = DetailsDialog.exec
    def mock_exec(self):
        dialog_captured.append(self)
        return DetailsDialog.DialogCode.Accepted

    monkeypatch.setattr(DetailsDialog, "exec", mock_exec)

    page.btn_verify.click()
    assert len(dialog_captured) == 1
    assert dialog_captured[0].windowTitle() == "Report Signature Verification"
