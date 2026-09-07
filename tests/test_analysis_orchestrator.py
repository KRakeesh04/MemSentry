"""Tests for the AnalysisOrchestrator service."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock
from uuid import UUID, uuid4

import pytest

from memsentry.analysis.orchestrator import (
    AnalysisOrchestrator,
    AnalysisRunNotFoundError,
    EvidenceRecordNotFoundError,
)
from memsentry.models.analysis_run import (
    AnalysisRun,
    AnalysisRunStatus,
    HostOS,
)
from memsentry.models.evidence import Evidence, EvidenceOS, IntegrityStatus
from memsentry.models.plugin_run import PluginRun, PluginRunStatus
from memsentry.utils.hashing import compute_file_sha256
from memsentry.volatility.runner import VolatilityResult, VolatilityRunner


def make_evidence(tmp_path: Path, filename: str = "ram.raw") -> Evidence:
    file_path = tmp_path / filename
    file_path.write_bytes(b"RAM EVIDENCE DUMP DATA 12345")
    return Evidence(
        id=uuid4(),
        case_id=uuid4(),
        original_filename=filename,
        file_path=file_path,
        file_size_bytes=file_path.stat().st_size,
        sha256=compute_file_sha256(file_path),
        evidence_os=EvidenceOS.WINDOWS,
        integrity_status=IntegrityStatus.VERIFIED,
        registered_at=datetime.now(UTC),
    )


class FakeAnalysisRunRepository:
    def __init__(self, runs: list[AnalysisRun] | None = None) -> None:
        self.runs = {r.id: r for r in (runs or [])}

    def get_by_id(self, analysis_run_id: UUID) -> AnalysisRun | None:
        return self.runs.get(analysis_run_id)

    def mark_running(self, analysis_run_id: UUID) -> AnalysisRun:
        run = self.runs[analysis_run_id]
        updated = run.model_copy(
            update={"status": AnalysisRunStatus.RUNNING, "started_at": datetime.now(UTC)}
        )
        self.runs[analysis_run_id] = updated
        return updated

    def mark_completed(self, analysis_run_id: UUID) -> AnalysisRun:
        run = self.runs[analysis_run_id]
        updated = run.model_copy(
            update={
                "status": AnalysisRunStatus.COMPLETED,
                "completed_at": datetime.now(UTC),
            }
        )
        self.runs[analysis_run_id] = updated
        return updated

    def mark_completed_with_errors(
        self, analysis_run_id: UUID, error_message: str | None = None
    ) -> AnalysisRun:
        run = self.runs[analysis_run_id]
        updated = run.model_copy(
            update={
                "status": AnalysisRunStatus.COMPLETED_WITH_ERRORS,
                "completed_at": datetime.now(UTC),
                "error_message": error_message,
            }
        )
        self.runs[analysis_run_id] = updated
        return updated

    def mark_failed(self, analysis_run_id: UUID, error_message: str) -> AnalysisRun:
        run = self.runs[analysis_run_id]
        updated = run.model_copy(
            update={
                "status": AnalysisRunStatus.FAILED,
                "completed_at": datetime.now(UTC),
                "error_message": error_message,
            }
        )
        self.runs[analysis_run_id] = updated
        return updated


class FakePluginRunRepository:
    def __init__(self, plugin_runs: list[PluginRun] | None = None) -> None:
        self.plugin_runs = {pr.id: pr for pr in (plugin_runs or [])}

    def list_by_analysis_run(self, analysis_run_id: UUID) -> list[PluginRun]:
        return [
            pr for pr in self.plugin_runs.values() if pr.analysis_run_id == analysis_run_id
        ]

    def mark_running(self, plugin_run_id: UUID) -> PluginRun:
        prun = self.plugin_runs[plugin_run_id]
        updated = prun.model_copy(
            update={"status": PluginRunStatus.RUNNING, "started_at": datetime.now(UTC)}
        )
        self.plugin_runs[plugin_run_id] = updated
        return updated

    def mark_completed(
        self,
        plugin_run_id: UUID,
        raw_output_path: Path | None,
        raw_output_sha256: str | None,
    ) -> PluginRun:
        prun = self.plugin_runs[plugin_run_id]
        updated = prun.model_copy(
            update={
                "status": PluginRunStatus.COMPLETED,
                "completed_at": datetime.now(UTC),
                "raw_output_path": raw_output_path,
                "raw_output_sha256": raw_output_sha256,
            }
        )
        self.plugin_runs[plugin_run_id] = updated
        return updated

    def mark_failed(
        self,
        plugin_run_id: UUID,
        error_message: str,
        raw_output_path: Path | None = None,
        raw_output_sha256: str | None = None,
    ) -> PluginRun:
        prun = self.plugin_runs[plugin_run_id]
        updated = prun.model_copy(
            update={
                "status": PluginRunStatus.FAILED,
                "completed_at": datetime.now(UTC),
                "error_message": error_message,
                "raw_output_path": raw_output_path,
                "raw_output_sha256": raw_output_sha256,
            }
        )
        self.plugin_runs[plugin_run_id] = updated
        return updated


class FakeEvidenceRepository:
    def __init__(self, records: list[Evidence] | None = None) -> None:
        self.records = {e.id: e for e in (records or [])}

    def get_by_id(self, evidence_id: UUID) -> Evidence | None:
        return self.records.get(evidence_id)


def test_analysis_run_not_found(tmp_path: Path) -> None:
    ar_repo = FakeAnalysisRunRepository()
    pr_repo = FakePluginRunRepository()
    ev_repo = FakeEvidenceRepository()
    runner = MagicMock(spec=VolatilityRunner)

    orchestrator = AnalysisOrchestrator(
        ar_repo, pr_repo, ev_repo, runner, base_output_dir=tmp_path
    )

    with pytest.raises(AnalysisRunNotFoundError, match="AnalysisRun not found"):
        orchestrator.execute_analysis_run(uuid4())


def test_evidence_not_found(tmp_path: Path) -> None:
    run_id = uuid4()
    run = AnalysisRun(
        id=run_id,
        evidence_id=uuid4(),
        status=AnalysisRunStatus.PENDING,
        application_version="1.0.0",
        volatility_version="3.0.0",
        host_os=HostOS.WINDOWS,
        created_at=datetime.now(UTC),
    )
    ar_repo = FakeAnalysisRunRepository([run])
    pr_repo = FakePluginRunRepository()
    ev_repo = FakeEvidenceRepository()
    runner = MagicMock(spec=VolatilityRunner)

    orchestrator = AnalysisOrchestrator(
        ar_repo, pr_repo, ev_repo, runner, base_output_dir=tmp_path
    )

    with pytest.raises(EvidenceRecordNotFoundError, match="Evidence record not found"):
        orchestrator.execute_analysis_run(run_id)

    assert ar_repo.runs[run_id].status == AnalysisRunStatus.FAILED
    assert "Evidence record not found" in (ar_repo.runs[run_id].error_message or "")


def test_missing_evidence_file(tmp_path: Path) -> None:
    evidence = Evidence(
        id=uuid4(),
        case_id=uuid4(),
        original_filename="missing.raw",
        file_path=tmp_path / "missing.raw",
        file_size_bytes=100,
        sha256="a" * 64,
        evidence_os=EvidenceOS.WINDOWS,
        integrity_status=IntegrityStatus.VERIFIED,
        registered_at=datetime.now(UTC),
    )
    run_id = uuid4()
    run = AnalysisRun(
        id=run_id,
        evidence_id=evidence.id,
        status=AnalysisRunStatus.PENDING,
        application_version="1.0.0",
        volatility_version="3.0.0",
        host_os=HostOS.WINDOWS,
        created_at=datetime.now(UTC),
    )
    ar_repo = FakeAnalysisRunRepository([run])
    pr_repo = FakePluginRunRepository()
    ev_repo = FakeEvidenceRepository([evidence])
    runner = MagicMock(spec=VolatilityRunner)

    orchestrator = AnalysisOrchestrator(
        ar_repo, pr_repo, ev_repo, runner, base_output_dir=tmp_path
    )

    result_run = orchestrator.execute_analysis_run(run_id)

    assert result_run.status == AnalysisRunStatus.FAILED
    assert "file missing" in (result_run.error_message or "")


def test_successful_analysis_run_orchestration(tmp_path: Path) -> None:
    evidence = make_evidence(tmp_path)
    initial_mtime = evidence.file_path.stat().st_mtime

    run_id = uuid4()
    run = AnalysisRun(
        id=run_id,
        evidence_id=evidence.id,
        status=AnalysisRunStatus.PENDING,
        application_version="1.0.0",
        volatility_version="3.0.0",
        host_os=HostOS.WINDOWS,
        created_at=datetime.now(UTC),
    )
    prun_id = uuid4()
    prun = PluginRun(
        id=prun_id,
        analysis_run_id=run_id,
        plugin_name="windows.pslist",
        status=PluginRunStatus.PENDING,
        configuration={},
    )

    ar_repo = FakeAnalysisRunRepository([run])
    pr_repo = FakePluginRunRepository([prun])
    ev_repo = FakeEvidenceRepository([evidence])

    runner = MagicMock(spec=VolatilityRunner)

    def mock_run_plugin(
        evidence_path: Path,
        plugin_name: str,
        output_dir: Path,
        evidence_os: Any = None,
        timeout_seconds: float | None = 300.0,
    ) -> VolatilityResult:
        out_file = output_dir / "windows_pslist.json"
        out_file.write_text('{"processes": []}', encoding="utf-8")
        return VolatilityResult(
            success=True,
            plugin_name=plugin_name,
            return_code=0,
            output_path=out_file,
            stdout='{"processes": []}',
            stderr="",
        )

    runner.run_plugin.side_effect = mock_run_plugin

    orchestrator = AnalysisOrchestrator(
        ar_repo, pr_repo, ev_repo, runner, base_output_dir=tmp_path
    )

    final_run = orchestrator.execute_analysis_run(run_id)

    assert final_run.status == AnalysisRunStatus.COMPLETED
    assert final_run.completed_at is not None

    final_prun = pr_repo.plugin_runs[prun_id]
    assert final_prun.status == PluginRunStatus.COMPLETED
    assert final_prun.raw_output_path is not None
    assert final_prun.raw_output_sha256 == compute_file_sha256(final_prun.raw_output_path)

    # Ensure evidence file was not modified
    assert evidence.file_path.stat().st_mtime == initial_mtime

    # Verify VolatilityRunner arguments
    runner.run_plugin.assert_called_once()
    kwargs = runner.run_plugin.call_args.kwargs
    assert kwargs["evidence_path"] == evidence.file_path
    assert kwargs["plugin_name"] == "windows.pslist"
    assert kwargs["evidence_os"] == EvidenceOS.WINDOWS
    assert kwargs["timeout_seconds"] == 300.0


def test_partial_failure_completed_with_errors(tmp_path: Path) -> None:
    evidence = make_evidence(tmp_path)
    run_id = uuid4()
    run = AnalysisRun(
        id=run_id,
        evidence_id=evidence.id,
        status=AnalysisRunStatus.PENDING,
        application_version="1.0.0",
        volatility_version="3.0.0",
        host_os=HostOS.WINDOWS,
        created_at=datetime.now(UTC),
    )
    prun1 = PluginRun(
        id=uuid4(),
        analysis_run_id=run_id,
        plugin_name="windows.pslist",
        status=PluginRunStatus.PENDING,
        configuration={},
    )
    prun2 = PluginRun(
        id=uuid4(),
        analysis_run_id=run_id,
        plugin_name="windows.malfind",
        status=PluginRunStatus.PENDING,
        configuration={},
    )

    ar_repo = FakeAnalysisRunRepository([run])
    pr_repo = FakePluginRunRepository([prun1, prun2])
    ev_repo = FakeEvidenceRepository([evidence])

    runner = MagicMock(spec=VolatilityRunner)

    def mock_run_plugin(
        evidence_path: Path,
        plugin_name: str,
        output_dir: Path,
        evidence_os: Any = None,
        timeout_seconds: float | None = 300.0,
    ) -> VolatilityResult:
        if plugin_name == "windows.pslist":
            out_file = output_dir / "windows_pslist.json"
            out_file.write_text('{"processes": []}', encoding="utf-8")
            return VolatilityResult(
                success=True,
                plugin_name=plugin_name,
                return_code=0,
                output_path=out_file,
                stdout='{"processes": []}',
                stderr="",
            )
        return VolatilityResult(
            success=False,
            plugin_name=plugin_name,
            return_code=1,
            output_path=None,
            stdout="",
            stderr="Symbol table not found",
            error_message="Symbol table not found",
        )

    runner.run_plugin.side_effect = mock_run_plugin

    orchestrator = AnalysisOrchestrator(
        ar_repo, pr_repo, ev_repo, runner, base_output_dir=tmp_path
    )

    final_run = orchestrator.execute_analysis_run(run_id)

    assert final_run.status == AnalysisRunStatus.COMPLETED_WITH_ERRORS
    assert "1 of 2 plugin(s) failed" in (final_run.error_message or "")

    assert pr_repo.plugin_runs[prun1.id].status == PluginRunStatus.COMPLETED
    assert pr_repo.plugin_runs[prun2.id].status == PluginRunStatus.FAILED
    assert "Symbol table not found" in (pr_repo.plugin_runs[prun2.id].error_message or "")


def test_custom_timeout_via_orchestrator_init(tmp_path: Path) -> None:
    evidence = make_evidence(tmp_path)
    run_id = uuid4()
    run = AnalysisRun(
        id=run_id,
        evidence_id=evidence.id,
        status=AnalysisRunStatus.PENDING,
        application_version="1.0.0",
        volatility_version="3.0.0",
        host_os=HostOS.WINDOWS,
        created_at=datetime.now(UTC),
    )
    prun = PluginRun(
        id=uuid4(),
        analysis_run_id=run_id,
        plugin_name="windows.pslist",
        status=PluginRunStatus.PENDING,
        configuration={},
    )
    ar_repo = FakeAnalysisRunRepository([run])
    pr_repo = FakePluginRunRepository([prun])
    ev_repo = FakeEvidenceRepository([evidence])
    runner = MagicMock(spec=VolatilityRunner)

    out_file = tmp_path / "out.json"
    out_file.write_text("{}", encoding="utf-8")
    runner.run_plugin.return_value = VolatilityResult(
        success=True,
        plugin_name="windows.pslist",
        return_code=0,
        output_path=out_file,
        stdout="{}",
        stderr="",
    )

    orchestrator = AnalysisOrchestrator(
        ar_repo,
        pr_repo,
        ev_repo,
        runner,
        base_output_dir=tmp_path,
        timeout_seconds=600.0,
    )
    orchestrator.execute_analysis_run(run_id)

    kwargs = runner.run_plugin.call_args.kwargs
    assert kwargs["timeout_seconds"] == 600.0


def test_custom_timeout_via_execute_analysis_run(tmp_path: Path) -> None:
    evidence = make_evidence(tmp_path)
    run_id = uuid4()
    run = AnalysisRun(
        id=run_id,
        evidence_id=evidence.id,
        status=AnalysisRunStatus.PENDING,
        application_version="1.0.0",
        volatility_version="3.0.0",
        host_os=HostOS.WINDOWS,
        created_at=datetime.now(UTC),
    )
    prun = PluginRun(
        id=uuid4(),
        analysis_run_id=run_id,
        plugin_name="windows.pslist",
        status=PluginRunStatus.PENDING,
        configuration={},
    )
    ar_repo = FakeAnalysisRunRepository([run])
    pr_repo = FakePluginRunRepository([prun])
    ev_repo = FakeEvidenceRepository([evidence])
    runner = MagicMock(spec=VolatilityRunner)

    out_file = tmp_path / "out.json"
    out_file.write_text("{}", encoding="utf-8")
    runner.run_plugin.return_value = VolatilityResult(
        success=True,
        plugin_name="windows.pslist",
        return_code=0,
        output_path=out_file,
        stdout="{}",
        stderr="",
    )

    orchestrator = AnalysisOrchestrator(
        ar_repo,
        pr_repo,
        ev_repo,
        runner,
        base_output_dir=tmp_path,
        timeout_seconds=300.0,
    )
    orchestrator.execute_analysis_run(run_id, timeout_seconds=900.0)

    kwargs = runner.run_plugin.call_args.kwargs
    assert kwargs["timeout_seconds"] == 900.0


def test_empty_plugin_list(tmp_path: Path) -> None:
    evidence = make_evidence(tmp_path)
    run_id = uuid4()
    run = AnalysisRun(
        id=run_id,
        evidence_id=evidence.id,
        status=AnalysisRunStatus.PENDING,
        application_version="1.0.0",
        volatility_version="3.0.0",
        host_os=HostOS.WINDOWS,
        created_at=datetime.now(UTC),
    )
    ar_repo = FakeAnalysisRunRepository([run])
    pr_repo = FakePluginRunRepository([])
    ev_repo = FakeEvidenceRepository([evidence])
    runner = MagicMock(spec=VolatilityRunner)

    orchestrator = AnalysisOrchestrator(
        ar_repo, pr_repo, ev_repo, runner, base_output_dir=tmp_path
    )

    final_run = orchestrator.execute_analysis_run(run_id)

    assert final_run.status == AnalysisRunStatus.COMPLETED_WITH_ERRORS
    assert "No plugin runs configured" in (final_run.error_message or "")
