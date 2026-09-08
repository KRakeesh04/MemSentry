from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from uuid import UUID, uuid4

import pytest

from memsentry.models.analysis_run import AnalysisRunCreate, HostOS
from memsentry.models.case import CaseCreate
from memsentry.models.evidence import EvidenceCreate
from memsentry.storage.database import Database
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.volatility.adapter import PluginExecutionResult, VolatilityAdapterError
from memsentry.volatility.plugin_registry import PluginRegistry
from memsentry.volatility.plugin_runner import PluginRunner, PluginRunnerError

DISCOVERED_PLUGINS = {
    "windows.pslist.PsList": object,
    "linux.pslist.PsList": object,
    "mac.pslist.PsList": object,
}

PSLIST_JSON = json.dumps([{"PID": 4, "PPID": 0, "ImageFileName": "System"}])


@pytest.fixture
def db(tmp_path: Path) -> Database:
    database = Database(tmp_path / "test.db")
    database.initialize()
    return database


@pytest.fixture
def registry() -> PluginRegistry:
    return PluginRegistry(discovered_plugins=DISCOVERED_PLUGINS)


@pytest.fixture
def analysis_run_id(db: Database, tmp_path: Path) -> UUID:
    case = CaseRepository(db).create(CaseCreate(case_number="C-RUN", name="Runner test"))
    evidence = EvidenceRepository(db).create(
        EvidenceCreate(
            case_id=case.id,
            original_filename=f"evidence-{uuid4()}.raw",
            file_path=tmp_path / "evidence.raw",
            file_size_bytes=1,
            sha256="c" * 64,
            evidence_os=None,
        )
    )
    repo = AnalysisRunRepository(db)
    run = repo.create(
        AnalysisRunCreate(
            evidence_id=evidence.id,
            application_version="0.1.0",
            volatility_version="2",
            host_os=HostOS.LINUX,
        )
    )
    return run.id


def _make_runner(
    db: Database, tmp_path: Path, adapter: object | None = None
) -> PluginRunner:
    if adapter is None:
        adapter = SimpleNamespace(
            initialize=lambda os_type: None,
            run_plugin=lambda plugin_name, evidence_path: PluginExecutionResult(
                plugin_name=plugin_name,
                raw_output=PSLIST_JSON,
                volatility_version="2.0.0",
                duration_seconds=0.1,
            ),
        )
    return PluginRunner(
        adapter=adapter,
        plugin_registry=PluginRegistry(discovered_plugins=DISCOVERED_PLUGINS),
        plugin_run_repository=PluginRunRepository(db),
        artifact_repository=ArtifactRepository(db),
        raw_output_dir=tmp_path / "raw",
    )


def test_run_plugin_returns_completed_run_and_persists_artifacts(
    db: Database, tmp_path: Path, analysis_run_id: UUID
) -> None:
    runner = _make_runner(db, tmp_path)
    evidence = tmp_path / "image.raw"
    evidence.write_bytes(b"dummy")

    result = runner.run_plugin(str(evidence), analysis_run_id, "process_list", "windows")

    assert result["parsed_result"].processes[0].pid == 4
    assert result["plugin_run"].status == "completed"
    raw_path = Path(result["raw_output_path"])
    assert raw_path.exists()
    assert raw_path.suffix == ".json"

    artifacts = result["artifacts"]
    assert len(artifacts) == 1
    assert artifacts[0].artifact_type == "process"
    assert artifacts[0].pid == 4
    assert artifacts[0].plugin_run_id == result["plugin_run"].id
    # The normalized typed record is persisted inside original_data.
    assert artifacts[0].original_data["normalized"]["process_name"] == "System"
    assert artifacts[0].original_data["normalized"]["ppid"] == 0
    assert artifacts[0].original_data["PID"] == 4

    # The raw output was stored outside the (unmodified) evidence file.
    assert raw_path.read_text() == PSLIST_JSON
    assert evidence.read_bytes() == b"dummy"


def test_run_plugin_marks_failed_and_raises_on_adapter_error(
    db: Database, tmp_path: Path, analysis_run_id: UUID
) -> None:
    def failing_initialize(os_type: str) -> None:
        raise VolatilityAdapterError("boom")

    runner = _make_runner(db, tmp_path, adapter=SimpleNamespace(initialize=failing_initialize))
    evidence = tmp_path / "image.raw"
    evidence.write_bytes(b"dummy")

    with pytest.raises(PluginRunnerError):
        runner.run_plugin(str(evidence), analysis_run_id, "process_list", "windows")

    run = runner.plugin_run_repository.list_by_analysis_run(analysis_run_id)[0]
    assert run.status == "failed"
    assert "boom" in run.error_message


def test_run_plugin_persists_no_artifacts_when_parse_yields_none(
    db: Database, tmp_path: Path, analysis_run_id: UUID
) -> None:
    adapter = SimpleNamespace(
        initialize=lambda os_type: None,
        run_plugin=lambda plugin_name, evidence_path: PluginExecutionResult(
            plugin_name=plugin_name,
            raw_output=json.dumps([]),
            volatility_version="2.0.0",
            duration_seconds=0.1,
        ),
    )
    runner = _make_runner(db, tmp_path, adapter=adapter)
    evidence = tmp_path / "image.raw"
    evidence.write_bytes(b"dummy")

    result = runner.run_plugin(str(evidence), analysis_run_id, "process_list", "windows")

    assert result["artifacts"] == []
    assert result["plugin_run"].status == "completed"
    assert result["plugin_run"].raw_output_sha256


def test_run_plugin_rejects_unknown_parser(
    db: Database, tmp_path: Path, analysis_run_id: UUID, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _make_runner(db, tmp_path)
    evidence = tmp_path / "image.raw"
    evidence.write_bytes(b"dummy")

    monkeypatch.setattr(
        runner,
        "_parser_spec",
        lambda name: (_ for _ in ()).throw(PluginRunnerError("no parser")),
    )
    with pytest.raises(PluginRunnerError):
        runner.run_plugin(str(evidence), analysis_run_id, "process_list", "linux")
