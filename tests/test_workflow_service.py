from hashlib import sha256
from types import SimpleNamespace
from unittest.mock import Mock
from uuid import uuid4

import pytest
import volatility3.symbols

from memsentry.app.analysis_service import AnalysisService
from memsentry.app.workflow_service import IntegrityCheckError, WorkflowService
from memsentry.correlation.engine import CorrelationEngine
from memsentry.models.analysis_run import AnalysisRunCreate, HostOS
from memsentry.models.artifact import ArtifactCreate
from memsentry.models.case import CaseCreate
from memsentry.models.evidence import EvidenceCreate
from memsentry.models.plugin_run import PluginRunCreate
from memsentry.storage.database import Database
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.finding_evidence_repository import FindingEvidenceRepository
from memsentry.storage.repositories.finding_repository import (
    FindingRepository,
    FindingRepositoryError,
)
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.storage.repositories.workflow_repository import WorkflowRepository
from memsentry.volatility.adapter import VolatilityAdapter
from memsentry.volatility.plugin_runner import PluginRunnerError
from memsentry.volatility.symbol_manager import SymbolManager
from memsentry.yara.scanner import YaraError


@pytest.fixture
def registered(tmp_path):
    source = tmp_path / "synthetic.mem"
    source.write_bytes(b"synthetic memory fixture")
    db = Database(tmp_path / "test.sqlite3")
    db.initialize()
    case = CaseRepository(db).create(CaseCreate(case_number="TEST", name="Test"))
    evidence = EvidenceRepository(db).create(
        EvidenceCreate(
            case_id=case.id,
            original_filename=source.name,
            file_path=source,
            file_size_bytes=source.stat().st_size,
            sha256=sha256(source.read_bytes()).hexdigest(),
        )
    )
    run = AnalysisRunRepository(db).create(
        AnalysisRunCreate(
            evidence_id=evidence.id,
            application_version="test",
            volatility_version="test",
            host_os=HostOS.LINUX,
        )
    )
    return db, evidence, run


def test_every_operation_has_real_hash_gates(registered):
    db, evidence, run = registered
    service = WorkflowService(db)
    for stage in ("analyze", "investigate", "correlate", "findings", "report"):
        operation = Mock(return_value="result")
        assert service.execute(run.id, stage, operation) == "result"
        operation.assert_called_once()
        events = [
            event
            for event in service.events.list_events(evidence.id, run.id)
            if event["stage"] == stage and event["status"] == "completed"
        ]
        assert [event["phase"] for event in events] == ["before", "after", "operation"]
        assert all(event["actual_sha256"] == evidence.sha256 for event in events[:2])
    assert EvidenceRepository(db).get_by_id(evidence.id).sha256 == evidence.sha256


def test_mismatch_blocks_operation_and_preserves_baseline(registered):
    db, evidence, run = registered
    evidence.file_path.write_bytes(b"changed synthetic fixture")
    operation = Mock()
    with pytest.raises(IntegrityCheckError):
        WorkflowService(db).execute(run.id, "analyze", operation)
    operation.assert_not_called()
    stored = EvidenceRepository(db).get_by_id(evidence.id)
    assert stored.sha256 == evidence.sha256
    assert stored.integrity_status == "modified"
    assert WorkflowRepository(db).list_events(evidence.id, run.id)[-1]["status"] == "failed"


def test_post_operation_mutation_blocks_next_stage(registered):
    db, evidence, run = registered
    service = WorkflowService(db)
    with pytest.raises(IntegrityCheckError):
        service.execute(run.id, "analyze", lambda: evidence.file_path.write_bytes(b"changed"))
    operation = Mock()
    with pytest.raises(IntegrityCheckError):
        service.execute(run.id, "correlate", operation)
    operation.assert_not_called()
    events = service.events.list_events(evidence.id, run.id)
    assert events[-1]["phase"] == "after"
    assert events[-1]["status"] == "failed"
    assert not any(e["phase"] == "operation" and e["status"] == "completed" for e in events)


def test_operation_error_still_checks_evidence(registered):
    db, evidence, run = registered
    with pytest.raises(ValueError, match="plugin failure"):
        WorkflowService(db).execute(
            run.id, "analyze", Mock(side_effect=ValueError("plugin failure"))
        )
    events = WorkflowRepository(db).list_events(evidence.id, run.id)
    assert any(e["phase"] == "operation" and e["status"] == "failed" for e in events)
    assert events[-1]["phase"] == "after"
    assert events[-1]["actual_sha256"] == evidence.sha256


def test_analysis_service_uses_integrity_gates(registered):
    db, evidence, run = registered
    registry = Mock()
    registry.validate_selection.return_value = [SimpleNamespace(id="pslist")]
    runner = Mock()
    runner.plugin_run_repository.database = db
    runner.run_plugin.return_value = {"artifacts": []}
    service = AnalysisService(Mock(), registry, runner, Mock(), dump_path=str(evidence.file_path))
    assert len(service.run(run.id, ["pslist"])) == 3
    assert AnalysisRunRepository(db).get_by_id(run.id).status == "completed"
    assert (
        len(
            [
                event
                for event in WorkflowRepository(db).list_events(evidence.id, run.id)
                if event["phase"] == "after" and event["status"] == "completed"
            ]
        )
        == 3
    )


@pytest.mark.parametrize("os_type", ["windows", "linux", "mac"])
def test_analysis_prepares_missing_symbols_before_plugins(
    registered, tmp_path, monkeypatch, os_type
):
    db, evidence, run = registered
    monkeypatch.setattr(volatility3.symbols, "__path__", list(volatility3.symbols.__path__))
    manager = SymbolManager(str(tmp_path / "symbols"))
    adapter = VolatilityAdapter(manager)
    registry = Mock()
    registry.validate_selection.return_value = [SimpleNamespace(id="pslist")]
    runner = Mock()
    runner.plugin_run_repository.database = db

    def execute(**kwargs):
        assert manager.get_symbol_path(os_type).is_dir()
        assert str(manager.symbol_dir) in volatility3.symbols.__path__
        return {"artifacts": []}

    runner.run_plugin.side_effect = execute
    AnalysisService(
        adapter, registry, runner, Mock(), os_type=os_type, dump_path=str(evidence.file_path)
    ).run(run.id, ["pslist"])
    runner.run_plugin.assert_called_once()
    assert sha256(evidence.file_path.read_bytes()).hexdigest() == evidence.sha256


def test_symbol_setup_failure_stops_plugins_and_checks_integrity(registered, tmp_path):
    db, evidence, run = registered
    manager = SymbolManager(str(tmp_path / "symbols"))
    manager.get_symbol_path("windows").write_text("not a directory")
    registry = Mock()
    registry.validate_selection.return_value = [SimpleNamespace(id="pslist")]
    runner = Mock()
    runner.plugin_run_repository.database = db
    service = AnalysisService(
        VolatilityAdapter(manager), registry, runner, Mock(), dump_path=str(evidence.file_path)
    )
    with pytest.raises(FileExistsError):
        service.run(run.id, ["pslist"])
    runner.run_plugin.assert_not_called()
    assert AnalysisRunRepository(db).get_by_id(run.id).status == "failed"
    events = WorkflowRepository(db).list_events(evidence.id, run.id)
    assert events[-1]["phase"] == "after"
    assert events[-1]["actual_sha256"] == evidence.sha256


@pytest.fixture
def correlation_service(registered):
    db, evidence, run = registered
    registry = Mock()
    registry.validate_selection.return_value = [SimpleNamespace(id="malfind")]
    runner = Mock()
    runner.plugin_run_repository.database = db
    plugin = PluginRunRepository(db).create(
        PluginRunCreate(analysis_run_id=run.id, plugin_name="windows.malfind.Malfind")
    )
    artifact = ArtifactRepository(db).create(
        ArtifactCreate(
            analysis_run_id=run.id,
            plugin_run_id=plugin.id,
            artifact_type="memory_region",
            pid=42,
            original_data={
                "Protection": "PAGE_EXECUTE_READWRITE",
                "normalized": {
                    "process_name": "fixture.exe",
                    "private_memory": True,
                    "protection": "PAGE_EXECUTE_READWRITE",
                },
            },
            provenance={"source": "windows.malfind.Malfind", "row": 1},
        )
    )
    runner.run_plugin.return_value = {"artifacts": [artifact]}
    service = AnalysisService(Mock(), registry, runner, Mock(), dump_path=str(evidence.file_path))
    return service, artifact


@pytest.mark.parametrize("partial_failure", [False, True])
def test_analysis_correlates_and_persists_provenance(
    registered, correlation_service, partial_failure
):
    db, evidence, run = registered
    service, artifact = correlation_service
    if partial_failure:
        service.plugin_registry.validate_selection.return_value.append(SimpleNamespace(id="pslist"))
        service.plugin_runner.run_plugin.side_effect = [
            {"artifacts": [artifact]},
            PluginRunnerError("Synthetic plugin failure"),
        ]
    result = service.run(run.id, ["malfind"])
    findings = FindingRepository(db).list_by_analysis_run(run.id)
    assert [finding.rule_id for finding in findings] == ["MS-R001"]
    links = FindingEvidenceRepository(db).list_by_finding(findings[0].id)
    assert links[0].source_reference == str(artifact.id)
    assert links[0].plugin_run_id == artifact.plugin_run_id
    assert links[0].supporting_data["original_data"] == artifact.original_data
    assert ArtifactRepository(db).get_by_id(artifact.id).original_data == artifact.original_data
    assert result[-1]["findings"] == findings
    assert AnalysisRunRepository(db).get_by_id(run.id).status == (
        "completed_with_errors" if partial_failure else "completed"
    )
    events = WorkflowRepository(db).list_events(evidence.id, run.id)
    for stage in ("correlate", "findings"):
        checks = [e for e in events if e["stage"] == stage and e["phase"] != "operation"]
        assert {e["phase"] for e in checks if e["status"] == "completed"} == {"before", "after"}
    with pytest.raises(ValueError, match="already started"):
        service.run(run.id, ["malfind"])
    assert len(FindingRepository(db).list_by_analysis_run(run.id)) == 1


@pytest.mark.parametrize("mutate", [False, True])
def test_correlation_failure_blocks_finding_storage(registered, correlation_service, mutate):
    db, evidence, run = registered
    service, _ = correlation_service
    engine = CorrelationEngine()
    original = engine.correlate

    def correlate(artifacts, run_id):
        if mutate:
            evidence.file_path.write_bytes(b"changed synthetic fixture")
            return original(artifacts, run_id)
        raise RuntimeError("Synthetic correlation failure")

    engine.correlate = correlate
    service.correlation_engine = engine
    with pytest.raises(IntegrityCheckError if mutate else RuntimeError):
        service.run(run.id, ["malfind"])
    assert AnalysisRunRepository(db).get_by_id(run.id).status == "failed"
    assert FindingRepository(db).list_by_analysis_run(run.id) == []
    assert WorkflowRepository(db).list_events(evidence.id, run.id)[-1]["phase"] == "after"


def test_finding_batch_rolls_back_on_provenance_failure(registered, correlation_service):
    db, _, run = registered
    _, artifact = correlation_service
    finding = CorrelationEngine().correlate([artifact], run.id).findings[0]
    invalid_artifact = artifact.model_copy(update={"plugin_run_id": uuid4()})
    with pytest.raises(FindingRepositoryError):
        FindingRepository(db).create_many_with_evidence(
            [
                (finding, [artifact]),
                (finding, [invalid_artifact]),
            ]
        )
    assert FindingRepository(db).list_by_analysis_run(run.id) == []


def test_yara_failure_still_correlates_available_artifacts(registered, correlation_service):
    db, _, run = registered
    service, _ = correlation_service
    service.yara_scanner.scan.side_effect = YaraError("Synthetic YARA failure")
    results = service.run(run.id, ["malfind"], ["fixture.yar"])
    assert results[1]["yara_error"] == "Synthetic YARA failure"
    assert results[-1]["findings"]
    assert any("Synthetic YARA failure" in w for w in results[-1]["correlation"].warnings)
    assert AnalysisRunRepository(db).get_by_id(run.id).status == "completed_with_errors"


def test_finding_storage_failure_marks_run_failed(registered, correlation_service, monkeypatch):
    db, evidence, run = registered
    service, _ = correlation_service
    monkeypatch.setattr(
        FindingRepository, "create_many_with_evidence",
        Mock(side_effect=FindingRepositoryError("Synthetic storage failure")),
    )
    with pytest.raises(FindingRepositoryError, match="Synthetic storage failure"):
        service.run(run.id, ["malfind"])
    assert AnalysisRunRepository(db).get_by_id(run.id).status == "failed"
    events = WorkflowRepository(db).list_events(evidence.id, run.id)
    assert events[-1]["stage"] == "findings"
    assert events[-1]["phase"] == "after"
    assert events[-1]["actual_sha256"] == evidence.sha256
