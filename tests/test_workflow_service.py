from hashlib import sha256
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import volatility3.symbols

from memsentry.app.analysis_service import AnalysisService
from memsentry.app.workflow_service import IntegrityCheckError, WorkflowService
from memsentry.models.analysis_run import AnalysisRunCreate, HostOS
from memsentry.models.case import CaseCreate
from memsentry.models.evidence import EvidenceCreate
from memsentry.storage.database import Database
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.workflow_repository import WorkflowRepository
from memsentry.volatility.adapter import VolatilityAdapter
from memsentry.volatility.symbol_manager import SymbolManager


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
    assert len(service.run(run.id, ["pslist"])) == 2
    assert AnalysisRunRepository(db).get_by_id(run.id).status == "completed"
    assert (
        len(
            [
                event
                for event in WorkflowRepository(db).list_events(evidence.id, run.id)
                if event["phase"] == "after" and event["status"] == "completed"
            ]
        )
        == 1
    )


@pytest.mark.parametrize("os_type", ["windows", "linux", "mac"])
def test_analysis_prepares_missing_symbols_before_plugins(registered, tmp_path, monkeypatch, os_type):
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
