"""Tests for the AddEvidenceDialog widget."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import uuid4

import pytest
from PySide6.QtWidgets import QApplication

from memsentry.gui.add_evidence_dialog import AddEvidenceDialog
from memsentry.models.evidence import Evidence, EvidenceCreate, EvidenceOS, IntegrityStatus


class FakeEvidenceRepository:
    """Fake EvidenceRepository for GUI testing without SQLite dependency."""

    def __init__(self) -> None:
        self.records: list[Evidence] = []
        self.should_fail: bool = False

    def create(self, evidence_data: EvidenceCreate) -> Evidence:
        if self.should_fail:
            raise RuntimeError("Database write error")

        evidence = Evidence(
            id=uuid4(),
            case_id=evidence_data.case_id,
            original_filename=evidence_data.original_filename,
            file_path=evidence_data.file_path,
            file_size_bytes=evidence_data.file_size_bytes,
            sha256=evidence_data.sha256,
            evidence_os=evidence_data.evidence_os,
            integrity_status=IntegrityStatus.VERIFIED,
            registered_at=datetime.now(UTC),
        )
        self.records.append(evidence)
        return evidence


@pytest.fixture
def app() -> QApplication:
    return cast(QApplication, QApplication.instance() or QApplication([]))


@pytest.fixture
def sample_file(tmp_path: Path) -> Path:
    file_path = tmp_path / "memory_dump.raw"
    file_path.write_bytes(b"RAM MEMORY DUMP DATA SAMPLE 1234567890")
    return file_path


def test_dialog_initial_state(qtbot: Any, app: QApplication) -> None:
    repo = FakeEvidenceRepository()
    case_id = uuid4()
    dialog = AddEvidenceDialog(case_id, cast(Any, repo))
    qtbot.addWidget(dialog)

    assert dialog.windowTitle() == "Register Evidence"
    assert dialog.isModal()
    assert not dialog.register_button.isEnabled()
    assert dialog.filename_label.text() == "N/A"
    assert dialog.filesize_label.text() == "N/A"
    assert dialog.sha256_display.text() == ""


def test_live_acquisition_unavailable(qtbot: Any, app: QApplication) -> None:
    repo = FakeEvidenceRepository()
    dialog = AddEvidenceDialog(uuid4(), cast(Any, repo))
    qtbot.addWidget(dialog)

    assert not dialog.live_radio.isEnabled()
    assert dialog.offline_radio.isChecked()
    assert "MemSentry analyzes" in dialog.live_radio.toolTip()


def test_file_selection_and_sha256_calculation(
    qtbot: Any, app: QApplication, sample_file: Path
) -> None:
    repo = FakeEvidenceRepository()
    dialog = AddEvidenceDialog(uuid4(), cast(Any, repo))
    qtbot.addWidget(dialog)

    dialog.set_file_path(sample_file)

    qtbot.wait_until(
        lambda: dialog.sha256_display.text() != "",
        timeout=3000,
    )

    assert dialog.filename_label.text() == "memory_dump.raw"
    assert "38 bytes" in dialog.filesize_label.text()
    assert len(dialog.sha256_display.text()) == 64
    assert dialog.hash_status_label.text() == "SHA-256 verified"
    assert dialog.register_button.isEnabled()


def test_os_selection(qtbot: Any, app: QApplication, sample_file: Path) -> None:
    repo = FakeEvidenceRepository()
    dialog = AddEvidenceDialog(uuid4(), cast(Any, repo))
    qtbot.addWidget(dialog)

    dialog.set_file_path(sample_file)
    qtbot.wait_until(lambda: dialog.register_button.isEnabled(), timeout=3000)

    # Change OS combo to Linux
    index = dialog.os_combo.findData(EvidenceOS.LINUX)
    dialog.os_combo.setCurrentIndex(index)

    assert dialog.os_combo.currentData() == EvidenceOS.LINUX


def test_successful_evidence_registration(
    qtbot: Any, app: QApplication, sample_file: Path
) -> None:
    repo = FakeEvidenceRepository()
    case_id = uuid4()
    dialog = AddEvidenceDialog(case_id, cast(Any, repo))
    qtbot.addWidget(dialog)

    created_signal_emitted: list[Evidence] = []
    dialog.evidence_created.connect(created_signal_emitted.append)

    dialog.set_file_path(sample_file)
    qtbot.wait_until(lambda: dialog.register_button.isEnabled(), timeout=3000)

    index = dialog.os_combo.findData(EvidenceOS.WINDOWS)
    dialog.os_combo.setCurrentIndex(index)

    dialog.register_evidence()

    assert dialog.result() == dialog.DialogCode.Accepted
    assert len(repo.records) == 1
    assert repo.records[0].case_id == case_id
    assert repo.records[0].original_filename == "memory_dump.raw"
    assert repo.records[0].evidence_os == EvidenceOS.WINDOWS
    assert len(created_signal_emitted) == 1


def test_missing_file_handling(qtbot: Any, app: QApplication, tmp_path: Path) -> None:
    repo = FakeEvidenceRepository()
    dialog = AddEvidenceDialog(uuid4(), cast(Any, repo))
    qtbot.addWidget(dialog)

    missing_path = tmp_path / "non_existent.raw"
    dialog.set_file_path(missing_path)

    assert not dialog.register_button.isEnabled()
    assert "does not exist" in dialog.error_label.text()
    assert dialog.hash_status_label.text() == "Selected file does not exist"


def test_hashing_failure_handling(
    qtbot: Any, app: QApplication, sample_file: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    repo = FakeEvidenceRepository()
    dialog = AddEvidenceDialog(uuid4(), cast(Any, repo))
    qtbot.addWidget(dialog)

    def mock_compute_hash(path: Path) -> str:
        raise OSError("Disk read error")

    monkeypatch.setattr(
        "memsentry.gui.add_evidence_dialog.compute_file_sha256",
        mock_compute_hash,
    )

    dialog.set_file_path(sample_file)

    qtbot.wait_until(
        lambda: dialog.hash_status_label.text() == "Hashing failed",
        timeout=3000,
    )

    assert not dialog.register_button.isEnabled()
    assert "Disk read error" in dialog.error_label.text()


def test_repository_failure_handling(
    qtbot: Any, app: QApplication, sample_file: Path
) -> None:
    repo = FakeEvidenceRepository()
    repo.should_fail = True
    dialog = AddEvidenceDialog(uuid4(), cast(Any, repo))
    qtbot.addWidget(dialog)

    dialog.set_file_path(sample_file)
    qtbot.wait_until(lambda: dialog.register_button.isEnabled(), timeout=3000)

    dialog.register_evidence()

    assert "Could not register evidence: Database write error" in dialog.error_label.text()
    assert len(repo.records) == 0
