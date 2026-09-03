"""Analyse a memory dump with a mocked Volatility adapter and print the stored DB data.

This test wires together the full persistence pipeline (case, evidence, analysis
run, plugin run, artifacts) against a chosen memory dump file. The Volatility
adapter is mocked so the test is fast and offline; it does not open the real
dump, so the evidence image is never read or modified.

The target dump defaults to ``tests/memory_dumps/windows/sample-01.mem``. Point
the test at any other Windows/Linux/macOS dump without editing this file by
setting the ``MEMSENTRY_TEST_DUMP`` environment variable to any file path:

    MEMSENTRY_TEST_DUMP=/path/to/dump.dump pytest tests/analysis/test_memory_dump_analysis.py -s

The target OS (used for evidence metadata and plugin selection) is derived
automatically from the dump's parent folder name ("windows", "linux", or "mac"),
and can be forced with the ``MEMSENTRY_TEST_OS`` environment variable. The DB
contents are printed to stdout so the stored results can be inspected.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID

import pytest

from memsentry.models.analysis_run import AnalysisRunCreate, HostOS
from memsentry.models.case import CaseCreate
from memsentry.models.evidence import EvidenceCreate, EvidenceOS
from memsentry.storage.database import Database
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.volatility.adapter import PluginExecutionResult
from memsentry.volatility.plugin_registry import PluginRegistry
from memsentry.volatility.plugin_runner import PluginRunner

DISCOVERED_PLUGINS = {
    "windows.pslist.PsList": object,
    "linux.pslist.PsList": object,
    "mac.pslist.PsList": object,
    "windows.cmdline.CmdLine": object,
    "linux.psaux.PsAux": object,
    "mac.psaux.Psaux": object,
}

# Volatility plugin -> OS -> sample JSON rows (matches Volatility's JSON renderer).
PSLIST_ROWS = {
    "windows": [
        {"PID": 4, "PPID": 0, "ImageFileName": "System"},
        {"PID": 408, "PPID": 4, "ImageFileName": "smss.exe"},
        {"PID": 544, "PPID": 408, "ImageFileName": "csrss.exe"},
    ],
    "linux": [
        {"PID": 1, "PPID": 0, "comm": "systemd"},
        {"PID": 621, "PPID": 1, "comm": "sshd"},
        {"PID": 987, "PPID": 1, "comm": "bash"},
    ],
    "mac": [
        {"PID": 0, "PPID": 0, "name": "kernel_task"},
        {"PID": 1, "PPID": 0, "name": "launchd"},
        {"PID": 255, "PPID": 1, "name": "loginwindow"},
    ],
}
CMDLINE_ROWS = {
    "windows": [
        {"PID": 544, "ImageFileName": "csrss.exe", "Args": "C:\\Windows\\System32\\csrss.exe"}
    ],
    "linux": [{"PID": 987, "comm": "bash", "Args": "/bin/bash"}],
    "mac": [{"PID": 255, "name": "loginwindow", "Args": "/System/Library/LoginWindow"}],
}

# The plugin id -> volatility plugin name for every supported OS.
PLUGIN_NAMES = {
    "process_list": {
        "windows": "windows.pslist.PsList",
        "linux": "linux.pslist.PsList",
        "mac": "mac.pslist.PsList",
    },
    "command_line": {
        "windows": "windows.cmdline.CmdLine",
        "linux": "linux.psaux.PsAux",
        "mac": "mac.psaux.Psaux",
    },
}

# The plugins actually exercised for any OS.
PLUGIN_IDS = ["process_list", "command_line"]


def _default_dump_path() -> Path:
    """Resolve the configured memory dump path.

    Uses ``MEMSENTRY_TEST_DUMP`` when set, otherwise the bundled Windows sample.
    Changing to another dump only requires setting that environment variable.
    """
    overridden = os.environ.get("MEMSENTRY_TEST_DUMP")
    if overridden:
        return Path(overridden).expanduser().resolve()
    return (
        Path(__file__).resolve().parents[1] / "memory_dumps" / "windows" / "sample-01.mem"
    )


def _target_os(dump_path: Path) -> str:
    """Derive the target OS from the dump path, with an explicit override."""

    forced = os.environ.get("MEMSENTRY_TEST_OS")
    if forced:
        return forced.strip().lower()
    parent = dump_path.parent.name.lower()
    if parent in {"windows", "win", "win10", "win2012"}:
        return "windows"
    if parent in {"linux", "centos", "ubuntu", "debian"}:
        return "linux"
    if parent in {"mac", "macos", "darwin"}:
        return "mac"
    return "windows"


def _evidence_os(os_type: str) -> EvidenceOS:
    return {
        "windows": EvidenceOS.WINDOWS,
        "linux": EvidenceOS.LINUX,
        "mac": EvidenceOS.MACOS,
    }[os_type]


def _mock_adapter(os_type: str) -> SimpleNamespace:
    """Return a mock Volatility adapter returning deterministic per-OS output."""

    def run_plugin(plugin_name: str, evidence_path: str) -> PluginExecutionResult:
        if plugin_name == PLUGIN_NAMES["process_list"][os_type]:
            raw_output = json.dumps(PSLIST_ROWS[os_type])
        elif plugin_name == PLUGIN_NAMES["command_line"][os_type]:
            raw_output = json.dumps(CMDLINE_ROWS[os_type])
        else:
            raw_output = json.dumps([])
        return PluginExecutionResult(
            plugin_name=plugin_name,
            raw_output=raw_output,
            volatility_version="2.0.0",
            duration_seconds=0.01,
        )

    return SimpleNamespace(
        initialize=lambda os_type: None,
        run_plugin=run_plugin,
    )


@pytest.fixture
def db(tmp_path: Path) -> Database:
    database = Database(tmp_path / "analysis.db")
    database.initialize()
    return database


def _print_section(title: str) -> None:
    print(f"\n{'=' * 70}")
    print(f" {title}")
    print("=" * 70)


def _print_db_contents(
    db: Database,
    *,
    case_id: UUID,
    evidence_id: UUID,
    analysis_run_id: UUID,
) -> None:
    """Print all DB rows related to the analysis run (read-only)."""
    case_repo = CaseRepository(db)
    evidence_repo = EvidenceRepository(db)
    analysis_repo = AnalysisRunRepository(db)
    plugin_run_repo = PluginRunRepository(db)
    artifact_repo = ArtifactRepository(db)

    _print_section("CASE")
    case = case_repo.get_by_id(case_id)
    print(case.model_dump() if case else "no case")

    _print_section("EVIDENCE")
    for evidence in evidence_repo.list_by_case(case_id):
        print(evidence.model_dump())
        print('\n')

    _print_section("ANALYSIS RUNS")
    for run in analysis_repo.list_by_evidence(evidence_id):
        print(run.model_dump())
        print('\n')

    _print_section("PLUGIN RUNS")
    for plugin_run in plugin_run_repo.list_by_analysis_run(analysis_run_id):
        print(plugin_run.model_dump())
        print('\n')

    _print_section("ARTIFACTS")
    artifacts = artifact_repo.list_by_analysis_run(analysis_run_id)
    for artifact in artifacts:
        print(artifact.model_dump())
        print('\n')

@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.skipif(
    not _default_dump_path().exists(),
    reason="Configured memory dump does not exist; set MEMSENTRY_TEST_DUMP to a real dump file.",
)
def test_analyse_memory_dump_and_print_db_data(
    db: Database,
) -> None:
    """Analyse a memory dump and print the stored DB contents."""
    dump_path = _default_dump_path()
    os_type = _target_os(dump_path)

    print(f"\nAnalysing memory dump: {dump_path}")
    print(f"Target OS: {os_type}  (override with MEMSENTRY_TEST_OS)")
    print(f"Exists: {dump_path.exists()}  Size(bytes): {dump_path.stat().st_size}")

    # 1. Case + evidence (evidence references the read-only dump, it is not opened).
    case = CaseRepository(db).create(
        CaseCreate(
            case_number="DUMPTEST-001",
            name="Memory dump analysis test",
            description=f"Automated analysis of {dump_path.name} ({os_type})",
        )
    )
    evidence = EvidenceRepository(db).create(
        EvidenceCreate(
            case_id=case.id,
            original_filename=dump_path.name,
            file_path=dump_path,
            file_size_bytes=dump_path.stat().st_size,
            sha256="a" * 64,
            evidence_os=_evidence_os(os_type),
        )
    )

    # 2. Analysis run.
    analysis_repo = AnalysisRunRepository(db)
    analysis_run = analysis_repo.create(
        AnalysisRunCreate(
            evidence_id=evidence.id,
            application_version="0.1.0",
            volatility_version="2.0.0",
            host_os=HostOS.LINUX,
        )
    )
    analysis_repo.mark_running(analysis_run.id)

    # 3. Run the approved plugins through the runner with a mocked adapter.
    registry = PluginRegistry(
        discovered_plugins={
            name: type_ for name, type_ in DISCOVERED_PLUGINS.items() if name.startswith(f"{os_type}.")
        }
    )
    runner = PluginRunner(
        adapter=_mock_adapter(os_type),
        plugin_registry=registry,
        plugin_run_repository=PluginRunRepository(db),
        artifact_repository=ArtifactRepository(db),
        raw_output_dir=db.database_path.parent / "raw_output",
    )
    for plugin_id in PLUGIN_IDS:
        runner.run_plugin(str(dump_path), analysis_run.id, plugin_id, os_type)

    analysis_repo.mark_completed(analysis_run.id)

    ################################################################
    # OUTPUT: print the DB stored data
    ################################################################
    _print_db_contents(
        db,
        case_id=case.id,
        evidence_id=evidence.id,
        analysis_run_id=analysis_run.id,
    )
