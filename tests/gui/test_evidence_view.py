"""Tests for the EvidenceView widget."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from PySide6.QtWidgets import QApplication

from memsentry.gui.evidence_view import EvidenceView
from memsentry.models.case import Case, CaseStatus
from memsentry.models.evidence import Evidence, EvidenceCreate, EvidenceOS, IntegrityStatus
from memsentry.volatility.plugin_applicability import PluginApplicabilityService


def make_case(name: str = "Investigation 1") -> Case:
    now = datetime.now(UTC)
    return Case(
        id=uuid4(),
        case_number=f"CASE-{uuid4().hex[:6]}",
        name=name,
        description=None,
        status=CaseStatus.OPEN,
        created_at=now,
        updated_at=now,
    )


def make_evidence(
    case_id: UUID,
    filename: str = "memory_dump.raw",
    os_val: EvidenceOS | None = EvidenceOS.WINDOWS,
) -> Evidence:
    now = datetime.now(UTC)
    return Evidence(
        id=uuid4(),
        case_id=case_id,
        original_filename=filename,
        file_path=Path(f"/evidence/{filename}"),
        file_size_bytes=1048576,
        sha256="a" * 64,
        evidence_os=os_val,
        integrity_status=IntegrityStatus.VERIFIED,
        registered_at=now,
    )


class FakeEvidenceRepository:
    """Fake EvidenceRepository for GUI testing without SQLite dependency."""

    def __init__(self, initial_records: list[Evidence] | None = None) -> None:
        self.records: list[Evidence] = initial_records or []
        self.should_fail: bool = False

    def list_by_case(self, case_id: UUID) -> list[Evidence]:
        if self.should_fail:
            raise RuntimeError("Database query failure")
        return [e for e in self.records if e.case_id == case_id]

    def create(self, evidence_data: EvidenceCreate) -> Evidence:
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


def test_no_active_case_initial_state(qtbot: Any, app: QApplication) -> None:
    repo = FakeEvidenceRepository()
    view = EvidenceView(cast(Any, repo), PluginApplicabilityService)
    qtbot.addWidget(view)

    assert not view.add_button.isEnabled()
    assert "No case opened" in view.state_label.text()
    assert view.evidence_table.rowCount() == 0


def test_empty_evidence_state(qtbot: Any, app: QApplication) -> None:
    repo = FakeEvidenceRepository()
    view = EvidenceView(cast(Any, repo), PluginApplicabilityService)
    qtbot.addWidget(view)

    case = make_case()
    view.set_active_case(case)

    assert view.add_button.isEnabled()
    assert "No forensic evidence registered" in view.state_label.text()
    assert view.evidence_table.rowCount() == 0


def test_evidence_listing_and_case_isolation(qtbot: Any, app: QApplication) -> None:
    case_a = make_case("Case A")
    case_b = make_case("Case B")

    ev_a = make_evidence(case_a.id, "case_a_dump.raw", EvidenceOS.WINDOWS)
    ev_b = make_evidence(case_b.id, "case_b_dump.raw", EvidenceOS.LINUX)

    repo = FakeEvidenceRepository([ev_a, ev_b])
    view = EvidenceView(cast(Any, repo), PluginApplicabilityService)
    qtbot.addWidget(view)

    # Set case A
    view.set_active_case(case_a)
    assert view.evidence_table.rowCount() == 1
    assert view.evidence_table.item(0, 0).text() == "case_a_dump.raw"  # type: ignore[union-attr]

    # Switch to case B
    view.set_active_case(case_b)
    assert view.evidence_table.rowCount() == 1
    assert view.evidence_table.item(0, 0).text() == "case_b_dump.raw"  # type: ignore[union-attr]


def test_evidence_selection_and_details(qtbot: Any, app: QApplication) -> None:
    case = make_case()
    evidence = make_evidence(case.id, "target_ram.dmp", EvidenceOS.WINDOWS)
    repo = FakeEvidenceRepository([evidence])

    view = EvidenceView(cast(Any, repo), PluginApplicabilityService)
    qtbot.addWidget(view)
    view.set_active_case(case)

    # Select row 0
    view.evidence_table.selectRow(0)

    assert "target_ram.dmp" in view.detail_name_label.text()
    assert "1,048,576 bytes" in view.detail_size_label.text()
    assert "a" * 64 in view.detail_sha256_label.text()
    assert "Windows" in view.detail_os_label.text()


def test_plugin_applicability_display_windows(qtbot: Any, app: QApplication) -> None:
    case = make_case()
    evidence = make_evidence(case.id, "win_ram.raw", EvidenceOS.WINDOWS)
    repo = FakeEvidenceRepository([evidence])

    view = EvidenceView(cast(Any, repo), PluginApplicabilityService)
    qtbot.addWidget(view)
    view.set_active_case(case)

    view.evidence_table.selectRow(0)

    assert "applicable plugin(s) for Windows" in view.plugins_status_label.text()
    assert view.plugins_list.count() > 0

    items = [view.plugins_list.item(i).text() for i in range(view.plugins_list.count())]
    assert any("windows.pslist" in item for item in items)
    assert any("windows.info" in item for item in items)


def test_plugin_applicability_display_linux(qtbot: Any, app: QApplication) -> None:
    case = make_case()
    evidence = make_evidence(case.id, "linux_ram.lime", EvidenceOS.LINUX)
    repo = FakeEvidenceRepository([evidence])

    view = EvidenceView(cast(Any, repo), PluginApplicabilityService)
    qtbot.addWidget(view)
    view.set_active_case(case)

    view.evidence_table.selectRow(0)

    assert "applicable plugin(s) for Linux" in view.plugins_status_label.text()
    items = [view.plugins_list.item(i).text() for i in range(view.plugins_list.count())]
    assert any("linux.pslist" in item for item in items)
    assert any("linux.info" in item for item in items)


def test_plugin_applicability_unknown_os(qtbot: Any, app: QApplication) -> None:
    case = make_case()
    evidence = make_evidence(case.id, "unknown_ram.raw", None)
    repo = FakeEvidenceRepository([evidence])

    view = EvidenceView(cast(Any, repo), PluginApplicabilityService)
    qtbot.addWidget(view)
    view.set_active_case(case)

    view.evidence_table.selectRow(0)

    assert "Target OS is unknown" in view.plugins_status_label.text()
    assert view.plugins_list.count() == 0


def test_repository_error_handling(qtbot: Any, app: QApplication) -> None:
    repo = FakeEvidenceRepository()
    repo.should_fail = True

    view = EvidenceView(cast(Any, repo), PluginApplicabilityService)
    qtbot.addWidget(view)

    case = make_case()
    view.set_active_case(case)

    assert "Unable to load evidence: Database query failure" in view.state_label.text()


def test_handle_evidence_created_refreshes_and_selects(
    qtbot: Any, app: QApplication
) -> None:
    case = make_case()
    repo = FakeEvidenceRepository()

    view = EvidenceView(cast(Any, repo), PluginApplicabilityService)
    qtbot.addWidget(view)
    view.set_active_case(case)

    assert view.evidence_table.rowCount() == 0

    new_evidence = make_evidence(case.id, "newly_registered.raw", EvidenceOS.WINDOWS)
    repo.records.append(new_evidence)

    view.handle_evidence_created(new_evidence)

    assert view.evidence_table.rowCount() == 1
    assert view.evidence_table.item(0, 0).text() == "newly_registered.raw"  # type: ignore[union-attr]
    assert "newly_registered.raw" in view.detail_name_label.text()
