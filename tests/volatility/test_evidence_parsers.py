"""Columns verified against installed Volatility 3; synthetic renderer rows only."""

from __future__ import annotations

import json
from types import SimpleNamespace

from tests.telemetry.test_imports import registered  # noqa: F401

from memsentry.correlation import CorrelationEngine
from memsentry.models.plugin_run import PluginRunCreate
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.volatility.plugin_registry import PluginRegistry
from memsentry.volatility.plugin_runner import PARSER_SPECS, PluginRunner
from memsentry.volatility.plugins.evidence_parsers import (
    PsScanParser,
    ThreadsParser,
    VadInfoParser,
)


def test_threads_choose_user_mode_address_and_preserve_raw():
    row = {
        "PID": 10,
        "TID": 12,
        "StartAddress": "0xffff0000",
        "Win32StartAddress": "0x1500",
        "CreateTime": "2026-01-01T00:00:00Z",
    }
    parsed = ThreadsParser().parse([row], "windows")
    assert parsed.threads[0].start_address == 0x1500
    assert parsed.threads[0].kernel_start_address == 0xFFFF0000
    assert parsed.threads[0].original_data == row
    assert parsed.threads[0].start_address_source == "Win32StartAddress"
    assert ThreadsParser().parse([{"PID": 10, "StartAddress": "invalid"}], "windows").warnings


def test_scan_keeps_provenance_and_termination():
    row = {
        "PID": 10,
        "PPID": 1,
        "ImageFileName": "synthetic.exe",
        "CreateTime": "2026-01-01T00:00:00Z",
        "ExitTime": "2026-01-01T00:10:00Z",
    }
    parsed = PsScanParser().parse(json.dumps([row]), "windows")
    process = parsed.processes[0]
    assert process.provenance["source_plugin"] == "windows.psscan.PsScan"
    assert process.provenance["process_view"] == "scan"
    assert process.exited_at == row["ExitTime"]


def test_vad_missing_file_is_not_unbacked_module():
    parsed = VadInfoParser().parse(
        [
            {
                "PID": 10,
                "Start VPN": "0x1000",
                "End VPN": "0x1fff",
                "Protection": "PAGE_EXECUTE_READ",
                "PrivateMemory": 1,
            }
        ],
        "windows",
    )
    assert parsed.regions[0].backing == "ANONYMOUS"
    assert parsed.regions[0].end_inclusive is True
    assert parsed.regions[0].provenance["source_plugin"] == "windows.vadinfo.VadInfo"


def test_runner_persists_new_parsers_and_engine_uses_actual_artifacts(registered, tmp_path):  # noqa: F811
    database, run, _ = registered
    plugins = PluginRunRepository(database)
    artifacts = ArtifactRepository(database)
    runner = PluginRunner(
        SimpleNamespace(),
        PluginRegistry(discovered_plugins={}),
        plugins,
        artifacts,
        raw_output_dir=tmp_path / "raw",
    )
    rows = {
        "vadinfo_parser": [
            {
                "PID": 10,
                "Start VPN": "0x1000",
                "End VPN": "0x2000",
                "Protection": "PAGE_EXECUTE_READ",
                "PrivateMemory": 1,
            }
        ],
        "threads_parser": [{"PID": 10, "TID": 11, "Win32StartAddress": "0x1500"}],
        "psscan_parser": [{"PID": 10, "PPID": 1, "ImageFileName": "synthetic.exe"}],
    }
    for name, values in rows.items():
        spec = PARSER_SPECS[name]
        plugin = plugins.create(PluginRunCreate(analysis_run_id=run.id, plugin_name=name))
        parsed = spec.parser.parse(values, "windows")
        runner._persist_artifacts(spec, parsed, run.id, plugin.id)
    saved = artifacts.list_by_analysis_run(run.id)
    result = CorrelationEngine().correlate(saved, run.id)
    assert {"MS-R001", "MS-R003"} <= {f.rule_id for f in result.findings}
    assert "MS-R008" not in {f.rule_id for f in result.findings}
    assert all(
        artifacts.get_by_id(key) is not None for ids in result.finding_artifact_ids for key in ids
    )
