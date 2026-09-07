"""Tests for main application window and wiring."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from uuid import UUID, uuid4

import pytest
from PySide6.QtWidgets import QApplication

from memsentry.gui.application import MainWindow, create_application
from memsentry.models.analysis_run import AnalysisRun
from memsentry.models.case import Case, CaseStatus
from memsentry.models.evidence import Evidence, EvidenceOS, IntegrityStatus
from memsentry.models.plugin_run import PluginRun


def make_case() -> Case:
    now = datetime.now(UTC)
    return Case(
        id=uuid4(),
        case_number="CASE-100",
        name="Test Investigation",
        description=None,
        status=CaseStatus.OPEN,
        created_at=now,
        updated_at=now,
    )


def make_evidence(case_id: UUID, filename: str = "ram.raw") -> Evidence:
    now = datetime.now(UTC)
    return Evidence(
        id=uuid4(),
        case_id=case_id,
        original_filename=filename,
        file_path=Path(f"/tmp/{filename}"),
        file_size_bytes=1024,
        sha256="a" * 64,
        evidence_os=EvidenceOS.WINDOWS,
        integrity_status=IntegrityStatus.VERIFIED,
        registered_at=now,
    )


class FakeCaseRepository:
    def __init__(self, cases: list[Case] | None = None) -> None:
        self.cases = cases or []

    def list_all(self) -> list[Case]:
        return self.cases

    def get_by_id(self, case_id: UUID) -> Case | None:
        return next((c for c in self.cases if c.id == case_id), None)


class FakeEvidenceRepository:
    def __init__(self) -> None:
        self.records: list[Evidence] = []

    def list_by_case(self, case_id: UUID) -> list[Evidence]:
        return [e for e in self.records if e.case_id == case_id]


class FakeAnalysisRunRepository:
    def list_by_evidence(self, evidence_id: UUID) -> list[AnalysisRun]:
        return []


class FakePluginRunRepository:
    def list_by_analysis_run(self, analysis_run_id: UUID) -> list[PluginRun]:
        return []


@pytest.fixture
def app() -> QApplication:
    return cast(QApplication, QApplication.instance() or QApplication([]))


def test_main_window_initial_state(qtbot: Any, app: QApplication) -> None:
    case_repo = FakeCaseRepository()
    evidence_repo = FakeEvidenceRepository()
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()

    window = MainWindow(
        cast(Any, case_repo),
        cast(Any, evidence_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
    )
    qtbot.addWidget(window)

    assert window.windowTitle() == "MemSentry"
    assert window.navigation.currentRow() == 0
    assert window.active_case is None
    assert window.evidence_view.active_case is None
    assert window.analysis_view.active_case is None


def test_main_window_open_case_updates_views(
    qtbot: Any, app: QApplication
) -> None:
    case = make_case()
    evidence = make_evidence(case.id, "mem_sample.raw")
    case_repo = FakeCaseRepository([case])
    evidence_repo = FakeEvidenceRepository()
    evidence_repo.records.append(evidence)
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()

    window = MainWindow(
        cast(Any, case_repo),
        cast(Any, evidence_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
    )
    qtbot.addWidget(window)

    window.open_case(case)

    assert window.active_case == case
    assert window.evidence_view.active_case == case
    assert window.analysis_view.active_case == case
    assert window.navigation.currentRow() == 1
    assert window.analysis_view.evidence_combo.count() == 1
    assert window.analysis_view.selected_evidence == evidence


def test_evidence_created_signal_updates_analysis_view(
    qtbot: Any, app: QApplication
) -> None:
    case = make_case()
    case_repo = FakeCaseRepository([case])
    evidence_repo = FakeEvidenceRepository()
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()

    window = MainWindow(
        cast(Any, case_repo),
        cast(Any, evidence_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
    )
    qtbot.addWidget(window)

    window.open_case(case)
    assert window.analysis_view.evidence_combo.count() == 0

    new_evidence = make_evidence(case.id, "new_mem.raw")
    evidence_repo.records.append(new_evidence)
    window.evidence_view.handle_evidence_created(new_evidence)

    assert window.analysis_view.evidence_combo.count() == 1
    assert window.analysis_view.selected_evidence == new_evidence


def test_create_application_bootstraps(qtbot: Any, app: QApplication) -> None:
    case_repo = FakeCaseRepository()
    evidence_repo = FakeEvidenceRepository()
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()

    created_app = create_application(
        cast(Any, case_repo),
        cast(Any, evidence_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
    )
    window = created_app.main_window  # type: ignore[attr-defined]

    assert isinstance(window, MainWindow)
    assert window.isVisible()
