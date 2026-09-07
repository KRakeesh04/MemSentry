"""Tests for the AnalysisView widget and AnalysisWorker integration."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from unittest.mock import MagicMock, patch
from uuid import UUID, uuid4

import pytest
from PySide6.QtCore import Qt
from PySide6.QtWidgets import QApplication

from memsentry.analysis.orchestrator import AnalysisOrchestrator
from memsentry.gui.analysis_view import AnalysisView, AnalysisWorker
from memsentry.models.analysis_run import (
    AnalysisRun,
    AnalysisRunCreate,
    AnalysisRunStatus,
    HostOS,
)
from memsentry.models.case import Case, CaseStatus
from memsentry.models.evidence import Evidence, EvidenceOS, IntegrityStatus
from memsentry.models.plugin_run import PluginRun, PluginRunCreate, PluginRunStatus
from memsentry.volatility.plugin_applicability import PluginApplicabilityService


def make_case() -> Case:
    now = datetime.now(UTC)
    return Case(
        id=uuid4(),
        case_number="CASE-001",
        name="Test Case",
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
        file_size_bytes=204800,
        sha256="c" * 64,
        evidence_os=os_val,
        integrity_status=IntegrityStatus.VERIFIED,
        registered_at=now,
    )


class FakeEvidenceRepository:
    def __init__(self, records: list[Evidence] | None = None) -> None:
        self.records = records or []
        self.should_fail = False

    def list_by_case(self, case_id: UUID) -> list[Evidence]:
        if self.should_fail:
            raise RuntimeError("Database connection error")
        return [e for e in self.records if e.case_id == case_id]


class FakeAnalysisRunRepository:
    def __init__(self, runs: list[AnalysisRun] | None = None) -> None:
        self.runs = {r.id: r for r in (runs or [])}
        self.should_fail = False

    def list_by_evidence(self, evidence_id: UUID) -> list[AnalysisRun]:
        if self.should_fail:
            raise RuntimeError("Database analysis query error")
        return [r for r in self.runs.values() if r.evidence_id == evidence_id]

    def create(self, data: AnalysisRunCreate) -> AnalysisRun:
        if self.should_fail:
            raise RuntimeError("Database analysis insert error")
        run = AnalysisRun(
            id=uuid4(),
            evidence_id=data.evidence_id,
            status=AnalysisRunStatus.PENDING,
            application_version=data.application_version,
            volatility_version=data.volatility_version,
            host_os=data.host_os,
            created_at=datetime.now(UTC),
        )
        self.runs[run.id] = run
        return run


class FakePluginRunRepository:
    def __init__(self, plugin_runs: list[PluginRun] | None = None) -> None:
        self.plugin_runs = {pr.id: pr for pr in (plugin_runs or [])}
        self.should_fail = False

    def list_by_analysis_run(self, analysis_run_id: UUID) -> list[PluginRun]:
        if self.should_fail:
            raise RuntimeError("Database plugin query error")
        return [pr for pr in self.plugin_runs.values() if pr.analysis_run_id == analysis_run_id]

    def create(self, data: PluginRunCreate) -> PluginRun:
        if self.should_fail:
            raise RuntimeError("Database plugin insert error")
        prun = PluginRun(
            id=uuid4(),
            analysis_run_id=data.analysis_run_id,
            plugin_name=data.plugin_name,
            status=PluginRunStatus.PENDING,
            configuration=data.configuration,
        )
        self.plugin_runs[prun.id] = prun
        return prun


@pytest.fixture
def app() -> QApplication:
    return cast(QApplication, QApplication.instance() or QApplication([]))


def test_no_active_case_initial_state(qtbot: Any, app: QApplication) -> None:
    ev_repo = FakeEvidenceRepository()
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()

    view = AnalysisView(
        cast(Any, ev_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
        PluginApplicabilityService,
    )
    qtbot.addWidget(view)

    assert "No case opened" in view.state_label.text()
    assert not view.evidence_combo.isEnabled()
    assert not view.run_button.isEnabled()


def test_active_case_with_no_evidence(qtbot: Any, app: QApplication) -> None:
    case = make_case()
    ev_repo = FakeEvidenceRepository()
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()

    view = AnalysisView(
        cast(Any, ev_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
        PluginApplicabilityService,
    )
    qtbot.addWidget(view)
    view.set_active_case(case)

    assert "No evidence registered" in view.state_label.text()
    assert view.evidence_combo.count() == 0
    assert not view.run_button.isEnabled()


def test_evidence_loading_and_selection(qtbot: Any, app: QApplication) -> None:
    case = make_case()
    ev1 = make_evidence(case.id, "win_ram.raw", EvidenceOS.WINDOWS)
    ev2 = make_evidence(case.id, "linux_ram.lime", EvidenceOS.LINUX)

    ev_repo = FakeEvidenceRepository([ev1, ev2])
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()

    view = AnalysisView(
        cast(Any, ev_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
        PluginApplicabilityService,
    )
    qtbot.addWidget(view)
    view.set_active_case(case)

    assert view.evidence_combo.count() == 2
    assert view.selected_evidence == ev1
    assert "win_ram.raw" in view.evidence_info_card.text()

    view.evidence_combo.setCurrentIndex(1)
    assert view.selected_evidence == ev2
    assert "linux_ram.lime" in view.evidence_info_card.text()


def test_os_aware_plugin_filtering(qtbot: Any, app: QApplication) -> None:
    case = make_case()
    win_ev = make_evidence(case.id, "win_ram.raw", EvidenceOS.WINDOWS)
    linux_ev = make_evidence(case.id, "linux_ram.lime", EvidenceOS.LINUX)

    ev_repo = FakeEvidenceRepository([win_ev, linux_ev])
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()

    view = AnalysisView(
        cast(Any, ev_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
        PluginApplicabilityService,
    )
    qtbot.addWidget(view)
    view.set_active_case(case)

    items_win = [
        view.plugins_list.item(i).text() for i in range(view.plugins_list.count())
    ]
    assert any("windows.pslist" in text for text in items_win)
    assert not any("linux.pslist" in text for text in items_win)

    view.evidence_combo.setCurrentIndex(1)
    items_linux = [
        view.plugins_list.item(i).text() for i in range(view.plugins_list.count())
    ]
    assert any("linux.pslist" in text for text in items_linux)
    assert not any("windows.pslist" in text for text in items_linux)


def test_analysis_worker_execution(qtbot: Any, app: QApplication) -> None:
    orchestrator = MagicMock(spec=AnalysisOrchestrator)
    run_id = uuid4()
    completed_run = AnalysisRun(
        id=run_id,
        evidence_id=uuid4(),
        status=AnalysisRunStatus.COMPLETED,
        application_version="1.0.0",
        volatility_version="3.0.0",
        host_os=HostOS.WINDOWS,
        created_at=datetime.now(UTC),
    )
    orchestrator.execute_analysis_run.return_value = completed_run

    worker = AnalysisWorker(orchestrator, run_id)
    finished_emitted: list[AnalysisRun] = []
    worker.finished.connect(finished_emitted.append)

    worker.start()
    qtbot.wait_until(lambda: len(finished_emitted) == 1, timeout=3000)

    orchestrator.execute_analysis_run.assert_called_once_with(run_id)
    assert finished_emitted[0] == completed_run


def test_analysis_worker_failure(qtbot: Any, app: QApplication) -> None:
    orchestrator = MagicMock(spec=AnalysisOrchestrator)
    run_id = uuid4()
    orchestrator.execute_analysis_run.side_effect = RuntimeError("Execution crashed")

    worker = AnalysisWorker(orchestrator, run_id)
    failed_emitted: list[str] = []
    worker.failed.connect(failed_emitted.append)

    worker.start()
    qtbot.wait_until(lambda: len(failed_emitted) == 1, timeout=3000)

    assert "Execution crashed" in failed_emitted[0]


def test_gui_async_analysis_execution_and_status_refresh(
    qtbot: Any, app: QApplication
) -> None:
    case = make_case()
    ev = make_evidence(case.id, "win_ram.raw", EvidenceOS.WINDOWS)

    ev_repo = FakeEvidenceRepository([ev])
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()

    orchestrator = MagicMock(spec=AnalysisOrchestrator)

    view = AnalysisView(
        cast(Any, ev_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
        PluginApplicabilityService,
        analysis_orchestrator=orchestrator,
    )
    qtbot.addWidget(view)
    view.set_active_case(case)

    # Configure side effect for execute_analysis_run
    def mock_execute(run_id: UUID) -> AnalysisRun:
        run = ar_repo.runs[run_id]
        updated = run.model_copy(
            update={"status": AnalysisRunStatus.COMPLETED_WITH_ERRORS, "error_message": "1 plugin failed"}
        )
        ar_repo.runs[run_id] = updated
        return updated

    orchestrator.execute_analysis_run.side_effect = mock_execute

    view.deselect_all_plugins()
    for i in range(view.plugins_list.count()):
        item = view.plugins_list.item(i)
        if item and "windows.pslist" in item.text():
            item.setCheckState(Qt.CheckState.Checked)

    view.run_analysis()

    # Verify controls disabled while running
    assert not view.run_button.isEnabled()
    assert not view.evidence_combo.isEnabled()
    assert "Running analysis" in view.state_label.text()

    # Wait for completion
    qtbot.wait_until(lambda: view.run_button.isEnabled(), timeout=3000)

    # Verify controls re-enabled and status updated
    assert "COMPLETED_WITH_ERRORS" in view.state_label.text()
    assert view.runs_table.rowCount() == 1
    assert "COMPLETED_WITH_ERRORS" in view.runs_table.item(0, 1).text()  # type: ignore[union-attr]


def test_duplicate_run_prevention(qtbot: Any, app: QApplication) -> None:
    case = make_case()
    ev = make_evidence(case.id, "win_ram.raw", EvidenceOS.WINDOWS)

    ev_repo = FakeEvidenceRepository([ev])
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()

    orchestrator = MagicMock(spec=AnalysisOrchestrator)

    view = AnalysisView(
        cast(Any, ev_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
        PluginApplicabilityService,
        analysis_orchestrator=orchestrator,
    )
    qtbot.addWidget(view)
    view.set_active_case(case)

    view.run_analysis()
    assert view.analysis_worker is not None

    # Call run_analysis again while worker is running
    view.run_analysis()
    assert "already in progress" in view.state_label.text()

    qtbot.wait_until(lambda: view.run_button.isEnabled(), timeout=3000)


def test_view_output_action_valid_file(
    qtbot: Any, app: QApplication, tmp_path: Path
) -> None:
    case = make_case()
    ev = make_evidence(case.id, "win_ram.raw", EvidenceOS.WINDOWS)

    out_file = tmp_path / "windows_pslist.json"
    out_file.write_text('{"processes": []}', encoding="utf-8")

    run_id = uuid4()
    ar = AnalysisRun(
        id=run_id,
        evidence_id=ev.id,
        status=AnalysisRunStatus.COMPLETED,
        application_version="1.0.0",
        volatility_version="3.0.0",
        host_os=HostOS.WINDOWS,
        created_at=datetime.now(UTC),
    )
    prun = PluginRun(
        id=uuid4(),
        analysis_run_id=run_id,
        plugin_name="windows.pslist",
        status=PluginRunStatus.COMPLETED,
        configuration={},
        raw_output_path=out_file,
        raw_output_sha256="1234",
    )

    ev_repo = FakeEvidenceRepository([ev])
    ar_repo = FakeAnalysisRunRepository([ar])
    pr_repo = FakePluginRunRepository([prun])

    view = AnalysisView(
        cast(Any, ev_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
        PluginApplicabilityService,
    )
    qtbot.addWidget(view)
    view.set_active_case(case)

    assert view.runs_table.rowCount() == 1
    assert view.plugin_runs_table.rowCount() == 1
    assert view.view_output_btn.isEnabled()

    with (
        MagicMock() as mock_open,
        patch("memsentry.gui.analysis_view.QDesktopServices.openUrl", mock_open),
    ):
        mock_open.return_value = True
        view.open_selected_plugin_output()
        mock_open.assert_called_once()
        assert "Opened output file" in view.state_label.text()


def test_view_output_action_missing_file(
    qtbot: Any, app: QApplication, tmp_path: Path
) -> None:
    case = make_case()
    ev = make_evidence(case.id, "win_ram.raw", EvidenceOS.WINDOWS)

    missing_file = tmp_path / "non_existent.json"
    run_id = uuid4()
    ar = AnalysisRun(
        id=run_id,
        evidence_id=ev.id,
        status=AnalysisRunStatus.COMPLETED,
        application_version="1.0.0",
        volatility_version="3.0.0",
        host_os=HostOS.WINDOWS,
        created_at=datetime.now(UTC),
    )
    prun = PluginRun(
        id=uuid4(),
        analysis_run_id=run_id,
        plugin_name="windows.pslist",
        status=PluginRunStatus.COMPLETED,
        configuration={},
        raw_output_path=missing_file,
    )

    ev_repo = FakeEvidenceRepository([ev])
    ar_repo = FakeAnalysisRunRepository([ar])
    pr_repo = FakePluginRunRepository([prun])

    view = AnalysisView(
        cast(Any, ev_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
        PluginApplicabilityService,
    )
    qtbot.addWidget(view)
    view.set_active_case(case)

    view.open_selected_plugin_output()
    assert "not found" in view.state_label.text()


def test_view_output_action_no_row_selected(qtbot: Any, app: QApplication) -> None:
    case = make_case()
    ev = make_evidence(case.id, "win_ram.raw", EvidenceOS.WINDOWS)

    ev_repo = FakeEvidenceRepository([ev])
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()

    view = AnalysisView(
        cast(Any, ev_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
        PluginApplicabilityService,
    )
    qtbot.addWidget(view)
    view.set_active_case(case)

    view.plugin_runs_table.clearSelection()
    view.plugin_runs_table.setCurrentCell(-1, -1)
    view.on_plugin_run_selected()

    assert not view.view_output_btn.isEnabled()

    view.open_selected_plugin_output()
    assert "No plugin run selected" in view.state_label.text()


def test_plugin_status_refresh_while_running(
    qtbot: Any, app: QApplication
) -> None:
    case = make_case()
    ev = make_evidence(case.id, "win_ram.raw", EvidenceOS.WINDOWS)

    ev_repo = FakeEvidenceRepository([ev])
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()

    orchestrator = MagicMock(spec=AnalysisOrchestrator)

    # Block execute_analysis_run from immediate return
    def slow_execute(run_id: UUID) -> AnalysisRun:
        import time

        time.sleep(0.2)
        run = ar_repo.runs[run_id]
        return run

    orchestrator.execute_analysis_run.side_effect = slow_execute

    view = AnalysisView(
        cast(Any, ev_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
        PluginApplicabilityService,
        analysis_orchestrator=orchestrator,
    )
    qtbot.addWidget(view)
    view.set_active_case(case)

    view.run_analysis()

    assert view.status_poll_timer.isActive()

    # Update plugin run status to RUNNING in fake repo while worker is executing
    prun_id = next(iter(pr_repo.plugin_runs.keys()))
    prun = pr_repo.plugin_runs[prun_id]
    pr_repo.plugin_runs[prun_id] = prun.model_copy(
        update={"status": PluginRunStatus.RUNNING}
    )

    # Emit timer timeout to poll status
    view.status_poll_timer.timeout.emit()

    assert view.plugin_runs_table.rowCount() == len(pr_repo.plugin_runs)
    assert view.plugin_runs_table.item(0, 1).text() == "RUNNING"  # type: ignore[union-attr]

    qtbot.wait_until(lambda: view.run_button.isEnabled(), timeout=3000)
    assert not view.status_poll_timer.isActive()


def test_timer_stops_after_analysis_completion(
    qtbot: Any, app: QApplication
) -> None:
    case = make_case()
    ev = make_evidence(case.id, "win_ram.raw", EvidenceOS.WINDOWS)

    ev_repo = FakeEvidenceRepository([ev])
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()
    orchestrator = MagicMock(spec=AnalysisOrchestrator)

    view = AnalysisView(
        cast(Any, ev_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
        PluginApplicabilityService,
        analysis_orchestrator=orchestrator,
    )
    qtbot.addWidget(view)
    view.set_active_case(case)

    view.run_analysis()
    assert view.status_poll_timer.isActive()

    qtbot.wait_until(lambda: view.run_button.isEnabled(), timeout=3000)
    assert not view.status_poll_timer.isActive()


def test_timer_stops_after_worker_failure(
    qtbot: Any, app: QApplication
) -> None:
    case = make_case()
    ev = make_evidence(case.id, "win_ram.raw", EvidenceOS.WINDOWS)

    ev_repo = FakeEvidenceRepository([ev])
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()

    orchestrator = MagicMock(spec=AnalysisOrchestrator)
    orchestrator.execute_analysis_run.side_effect = RuntimeError("Worker crashed")

    view = AnalysisView(
        cast(Any, ev_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
        PluginApplicabilityService,
        analysis_orchestrator=orchestrator,
    )
    qtbot.addWidget(view)
    view.set_active_case(case)

    view.run_analysis()
    assert view.status_poll_timer.isActive()

    qtbot.wait_until(lambda: view.run_button.isEnabled(), timeout=3000)
    assert not view.status_poll_timer.isActive()
    assert "Worker crashed" in view.state_label.text()


def test_repeated_start_does_not_create_duplicate_timers(
    qtbot: Any, app: QApplication
) -> None:
    case = make_case()
    ev = make_evidence(case.id, "win_ram.raw", EvidenceOS.WINDOWS)

    ev_repo = FakeEvidenceRepository([ev])
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()
    orchestrator = MagicMock(spec=AnalysisOrchestrator)

    def slow_execute(run_id: UUID) -> AnalysisRun:
        import time

        time.sleep(0.3)
        return ar_repo.runs[run_id]

    orchestrator.execute_analysis_run.side_effect = slow_execute

    view = AnalysisView(
        cast(Any, ev_repo),
        cast(Any, ar_repo),
        cast(Any, pr_repo),
        PluginApplicabilityService,
        analysis_orchestrator=orchestrator,
    )
    qtbot.addWidget(view)
    view.set_active_case(case)

    initial_timer = view.status_poll_timer

    view.run_analysis()
    assert view.status_poll_timer.isActive()

    # Attempt second run while worker is active
    view.run_analysis()
    assert view.status_poll_timer is initial_timer
    assert view.status_poll_timer.isActive()

    qtbot.wait_until(lambda: view.run_button.isEnabled(), timeout=3000)
    assert not view.status_poll_timer.isActive()
