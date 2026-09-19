import hashlib
import json
import sys
from types import SimpleNamespace

import pytest
import volatility3.symbols

from memsentry.app.analysis_job import AnalysisRequest, run_analysis
from memsentry.models.case import CaseCreate
from memsentry.models.evidence import EvidenceCreate
from memsentry.storage.database import Database
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.volatility.adapter import PluginExecutionResult
from memsentry.volatility.plugin_registry import PluginRegistry


@pytest.fixture
def job(tmp_path, monkeypatch):
    db = Database(tmp_path / "memsentry.sqlite3")
    db.initialize()
    case = CaseRepository(db).create(CaseCreate(case_number="TEST", name="Analysis test"))
    source = tmp_path / "fixture.mem"
    source.write_bytes(b"synthetic evidence only")
    evidence = EvidenceRepository(db).create(
        EvidenceCreate(
            case_id=case.id,
            original_filename=source.name,
            file_path=source,
            file_size_bytes=source.stat().st_size,
            sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
            evidence_os="windows",
        )
    )
    symbols = tmp_path / "symbols"
    (symbols / "windows").mkdir(parents=True)
    (symbols / "windows" / "fixture.json").write_text("{}")
    registry = PluginRegistry(discovered_plugins={"windows.pslist.PsList": object})
    monkeypatch.setattr("memsentry.app.analysis_job.PluginRegistry", lambda: registry)
    adapter = SimpleNamespace(
        initialize=lambda os_type: None,
        run_plugin=lambda name, path: PluginExecutionResult(
            name, json.dumps([{"PID": 4, "PPID": 0, "ImageFileName": "System"}]), "test", 0.1
        ),
    )
    monkeypatch.setattr(
        "memsentry.app.analysis_job.VolatilityAdapter", lambda *args, **kwargs: adapter
    )
    return (
        db,
        evidence,
        AnalysisRequest(str(tmp_path), evidence.id, "windows", ("process_list",), symbols),
    )


def test_background_job_persists_volatility_and_yara(job, tmp_path, monkeypatch):
    from dataclasses import replace

    db, evidence, request = job
    rule = tmp_path / "test.yar"
    rule.write_text("rule test { condition: true }")
    match = SimpleNamespace(rule="test", namespace="test", tags=[], meta={}, strings=[])
    monkeypatch.setitem(
        sys.modules,
        "yara",
        SimpleNamespace(compile=lambda **kwargs: SimpleNamespace(match=lambda path: [match])),
    )
    paths = list(volatility3.symbols.__path__)
    started = []
    run = run_analysis(replace(request, yara_rules=(rule,)), started.append)
    assert run.status == "completed"
    assert started[0].id == run.id
    assert list(volatility3.symbols.__path__) == paths
    plugins = PluginRunRepository(db).list_by_analysis_run(run.id)
    assert {plugin.plugin_name for plugin in plugins} == {"windows.pslist.PsList", "yara.scan"}
    assert len(ArtifactRepository(db).list_by_analysis_run(run.id)) == 2
    assert hashlib.sha256(evidence.file_path.read_bytes()).hexdigest() == evidence.sha256
    manifest = (
        tmp_path / "cases" / str(evidence.case_id) / "analysis" / str(run.id) / "selection.json"
    )
    assert json.loads(manifest.read_text())["yara_requested"] is True


def test_job_rejects_wrong_os(job):
    from dataclasses import replace

    _, _, request = job
    with pytest.raises(ValueError, match="does not match"):
        run_analysis(replace(request, os_type="linux"))


def test_yara_modern_string_instances():
    from memsentry.yara.scanner import YaraScanner

    match = SimpleNamespace(
        rule="test",
        strings=[
            SimpleNamespace(
                identifier="$a", instances=[SimpleNamespace(offset=12, matched_data=b"sample")]
            )
        ],
    )
    normalized = YaraScanner._normalize_match(match)
    assert normalized.strings[0] == {"offset": 12, "identifier": "$a", "data_hex": b"sample".hex()}


def test_independent_plugins_continue_after_failure(job, monkeypatch):
    from dataclasses import replace

    from memsentry.volatility.adapter import VolatilityAdapterError

    db, _, request = job
    registry = PluginRegistry(
        discovered_plugins={"windows.pslist.PsList": object, "windows.pstree.PsTree": object}
    )
    monkeypatch.setattr("memsentry.app.analysis_job.PluginRegistry", lambda: registry)

    def execute(name, path):
        if name == "windows.pslist.PsList":
            raise VolatilityAdapterError("Synthetic plugin failure")
        return PluginExecutionResult(name, "[]", "test", 0.1)

    monkeypatch.setattr(
        "memsentry.app.analysis_job.VolatilityAdapter",
        lambda *args, **kwargs: SimpleNamespace(
            initialize=lambda os_type: None, run_plugin=execute
        ),
    )
    run = run_analysis(replace(request, plugin_ids=("process_list", "process_tree")))
    assert run.status == "completed_with_errors"
    assert "Synthetic plugin failure" in run.error_message
    assert {plugin.status for plugin in PluginRunRepository(db).list_by_analysis_run(run.id)} == {
        "completed",
        "failed",
    }
