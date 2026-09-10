"""Unit tests for ArtifactService and ProcessItemViewModel mapping."""

from __future__ import annotations

from datetime import UTC, datetime
from uuid import uuid4

import pytest

from memsentry.app.artifact_service import ArtifactService, ProcessItemViewModel
from memsentry.models.analysis_run import AnalysisRun, AnalysisRunStatus, HostOS
from memsentry.models.artifact import Artifact
from memsentry.models.plugin_run import PluginRun, PluginRunStatus


class FakeAnalysisRunRepository:
    def __init__(self, runs: list[AnalysisRun] | None = None) -> None:
        self.runs: list[AnalysisRun] = runs or []

    def list_by_evidence(self, evidence_id: object) -> list[AnalysisRun]:
        return [r for r in self.runs if r.evidence_id == evidence_id]


class FakeArtifactRepository:
    def __init__(self, artifacts: list[Artifact] | None = None) -> None:
        self.artifacts: list[Artifact] = artifacts or []

    def list_by_type(self, analysis_run_id: object, artifact_type: str) -> list[Artifact]:
        return [
            a
            for a in self.artifacts
            if a.analysis_run_id == analysis_run_id and a.artifact_type == artifact_type
        ]


def test_artifact_service_no_analysis_runs() -> None:
    ar_repo = FakeAnalysisRunRepository([])
    art_repo = FakeArtifactRepository([])
    service = ArtifactService(art_repo, ar_repo)  # type: ignore[arg-type]

    evidence_id = uuid4()
    run = service.get_latest_analysis_run_for_evidence(evidence_id)
    assert run is None

    procs = service.get_processes_for_analysis_run(uuid4())
    assert procs == []


def test_artifact_service_process_correlation() -> None:
    evidence_id = uuid4()
    run_id = uuid4()
    plugin_run_id = uuid4()
    now = datetime.now(UTC)

    analysis_run = AnalysisRun(
        id=run_id,
        evidence_id=evidence_id,
        status=AnalysisRunStatus.COMPLETED,
        application_version="1.0.0",
        volatility_version="3.0.0",
        host_os=HostOS.WINDOWS,
        created_at=now,
        started_at=now,
        completed_at=now,
    )

    # Process artifact
    proc_art = Artifact(
        id=uuid4(),
        analysis_run_id=run_id,
        plugin_run_id=plugin_run_id,
        artifact_type="process",
        original_data={
            "PID": 404,
            "PPID": 100,
            "ImageFileName": "svchost.exe",
            "Threads": 12,
            "Handles": 140,
            "CreateTime": "2024-11-15T06:00:00Z",
        },
        provenance={"plugin_name": "windows.pslist"},
        created_at=now,
    )

    # Cmdline artifact
    cmd_art = Artifact(
        id=uuid4(),
        analysis_run_id=run_id,
        plugin_run_id=plugin_run_id,
        artifact_type="command_line",
        original_data={
            "PID": 404,
            "Process": "svchost.exe",
            "Args": "C:\\Windows\\System32\\svchost.exe -k netsvcs",
        },
        provenance={"plugin_name": "windows.pslist"},
        created_at=now,
    )

    # Malfind artifact
    mal_art = Artifact(
        id=uuid4(),
        analysis_run_id=run_id,
        plugin_run_id=plugin_run_id,
        artifact_type="memory_region",
        original_data={
            "PID": 404,
            "Process": "svchost.exe",
            "StartVAD": "0x7ff0000",
            "Protection": "PAGE_EXECUTE_READWRITE",
            "Notes": "Unbacked executable memory block",
        },
        provenance={"plugin_name": "windows.pslist"},
        created_at=now,
    )

    # Netscan artifact
    net_art = Artifact(
        id=uuid4(),
        analysis_run_id=run_id,
        plugin_run_id=plugin_run_id,
        artifact_type="network_connection",
        original_data={
            "PID": 404,
            "Owner": "svchost.exe",
            "LocalAddr": "192.168.1.50:49152",
            "ForeignAddr": "198.51.100.4:443",
            "State": "ESTABLISHED",
        },
        provenance={"plugin_name": "windows.pslist"},
        created_at=now,
    )

    # Dlllist artifact
    dll_art = Artifact(
        id=uuid4(),
        analysis_run_id=run_id,
        plugin_run_id=plugin_run_id,
        artifact_type="module",
        original_data={
            "PID": 404,
            "Process": "svchost.exe",
            "Path": "C:\\Windows\\System32\\ntdll.dll",
        },
        provenance={"plugin_name": "windows.pslist"},
        created_at=now,
    )

    ar_repo = FakeAnalysisRunRepository([analysis_run])
    art_repo = FakeArtifactRepository([proc_art, cmd_art, mal_art, net_art, dll_art])

    service = ArtifactService(art_repo, ar_repo)  # type: ignore[arg-type]

    procs = service.get_processes_for_analysis_run(run_id)
    assert len(procs) == 1
    p = procs[0]
    assert p.pid == 404
    assert p.ppid == 100
    assert p.name == "svchost.exe"
    assert p.command_line == "C:\\Windows\\System32\\svchost.exe -k netsvcs"
    assert p.is_suspicious is True
    assert "Injected RWX memory region" in p.threat_description
    assert len(p.sockets) == 1
    assert "198.51.100.4" in p.sockets[0]
    assert len(p.modules) == 1
    assert p.modules[0] == "C:\\Windows\\System32\\ntdll.dll"


def test_artifact_service_linux_not_applicable() -> None:
    evidence_id = uuid4()
    run_id = uuid4()
    now = datetime.now(UTC)

    analysis_run = AnalysisRun(
        id=run_id,
        evidence_id=evidence_id,
        status=AnalysisRunStatus.COMPLETED,
        application_version="1.0.0",
        volatility_version="3.0.0",
        host_os=HostOS.WINDOWS,
        created_at=now,
        started_at=now,
        completed_at=now,
    )

    # Linux process without Handles/Session
    proc_art = Artifact(
        id=uuid4(),
        analysis_run_id=run_id,
        plugin_run_id=uuid4(),
        artifact_type="process",
        original_data={
            "PID": 1234,
            "PPID": 1,
            "ImageFileName": "nginx",
        },
        provenance={"plugin_name": "linux.pslist"},
        created_at=now,
    )

    ar_repo = FakeAnalysisRunRepository([analysis_run])
    art_repo = FakeArtifactRepository([proc_art])

    service = ArtifactService(art_repo, ar_repo)  # type: ignore[arg-type]
    procs = service.get_processes_for_analysis_run(run_id)
    assert len(procs) == 1
    p = procs[0]
    assert p.handles == "Not Applicable"
    assert p.session == "Not Applicable"


def test_artifact_service_filter_processes() -> None:
    vm1 = ProcessItemViewModel(
        pid=100,
        name="explorer.exe",
        sockets=["192.168.1.10 -> 10.0.0.1 (ESTABLISHED)"],
        provenance_plugin="windows.pslist",
    )
    vm2 = ProcessItemViewModel(
        pid=200,
        name="powershell.exe",
        command_line="powershell.exe -enc AAAA",
        is_suspicious=True,
        memory_regions=["PAGE_EXECUTE_READWRITE"],
        provenance_plugin="windows.malfind",
    )

    all_vms = [vm1, vm2]

    # Filter by name
    assert len(ArtifactService.filter_processes(all_vms, "explorer")) == 1
    # Filter by PID
    assert len(ArtifactService.filter_processes(all_vms, "200")) == 1
    # Filter by IP
    assert len(ArtifactService.filter_processes(all_vms, "10.0.0.1")) == 1
    # Filter by plugin
    assert len(ArtifactService.filter_processes(all_vms, "malfind")) == 1
    # Filter by severity
    assert len(ArtifactService.filter_processes(all_vms, "suspicious")) == 1
    # Filter non-matching
    assert len(ArtifactService.filter_processes(all_vms, "nonexistent")) == 0

