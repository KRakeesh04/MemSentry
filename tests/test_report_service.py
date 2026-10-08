import json
from hashlib import sha256
from uuid import uuid4

import pytest

from memsentry.app.report_service import ReportService
from memsentry.models.case import CaseCreate
from memsentry.models.evidence import EvidenceCreate
from memsentry.models.report import ReportOptions
from memsentry.reports.exporters.html_exporter import HtmlReportExporter
from memsentry.reports.exporters.json_exporter import JsonReportExporter
from memsentry.storage.database import Database
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.finding_repository import FindingRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.storage.repositories.workflow_repository import WorkflowRepository


@pytest.fixture
def registered_db(tmp_path):
    db = Database(tmp_path / "test_report.sqlite3")
    db.initialize()

    case_repo = CaseRepository(db)
    evidence_repo = EvidenceRepository(db)

    case = case_repo.create(CaseCreate(case_number="RPT-123", name="Report Test Case"))

    source = tmp_path / "dummy.mem"
    source.write_bytes(b"dummy")
    evidence = evidence_repo.create(
        EvidenceCreate(
            case_id=case.id,
            original_filename=source.name,
            file_path=source,
            file_size_bytes=source.stat().st_size,
            sha256=sha256(source.read_bytes()).hexdigest(),
        )
    )

    # Some events
    WorkflowRepository(db).record(
        evidence_id=evidence.id,
        run_id=None,
        stage="case",
        phase="operation",
        status="completed",
        message="Created test evidence",
    )

    return db, case, evidence


def test_report_service_basic_aggregation(registered_db):
    db, case, evidence = registered_db

    service = ReportService(
        CaseRepository(db),
        EvidenceRepository(db),
        AnalysisRunRepository(db),
        PluginRunRepository(db),
        FindingRepository(db),
        ArtifactRepository(db),
        WorkflowRepository(db),
    )

    opts = ReportOptions()
    report = service.aggregate_report_data(case.id, opts)

    assert report.case.case_number == "RPT-123"
    assert len(report.evidences) == 1
    assert report.evidences[0].original_filename == "dummy.mem"
    assert len(report.findings) == 0
    assert report.plugin_runs is None
    assert report.artifacts is None
    assert report.workflow_events is None


def test_report_service_with_options(registered_db):
    db, case, evidence = registered_db

    service = ReportService(
        CaseRepository(db),
        EvidenceRepository(db),
        AnalysisRunRepository(db),
        PluginRunRepository(db),
        FindingRepository(db),
        ArtifactRepository(db),
        WorkflowRepository(db),
    )

    opts = ReportOptions(include_workflow_history=True, include_plugin_runs=True)
    report = service.aggregate_report_data(case.id, opts)

    assert report.workflow_events is not None
    assert len(report.workflow_events) == 1
    assert report.workflow_events[0]["message"] == "Created test evidence"

    assert report.plugin_runs is not None
    assert len(report.plugin_runs) == 0


def test_json_exporter(registered_db, tmp_path):
    db, case, evidence = registered_db
    service = ReportService(
        CaseRepository(db),
        EvidenceRepository(db),
        AnalysisRunRepository(db),
        PluginRunRepository(db),
        FindingRepository(db),
        ArtifactRepository(db),
        WorkflowRepository(db),
    )
    report = service.aggregate_report_data(case.id, ReportOptions())

    out_file = tmp_path / "report.json"
    exporter = JsonReportExporter()
    exporter.export(report, out_file)

    assert out_file.exists()
    data = json.loads(out_file.read_text())
    assert data["case"]["case_number"] == "RPT-123"
    assert data["evidences"][0]["sha256"] == evidence.sha256


def test_html_exporter(registered_db, tmp_path):
    db, case, evidence = registered_db
    service = ReportService(
        CaseRepository(db),
        EvidenceRepository(db),
        AnalysisRunRepository(db),
        PluginRunRepository(db),
        FindingRepository(db),
        ArtifactRepository(db),
        WorkflowRepository(db),
    )
    report = service.aggregate_report_data(case.id, ReportOptions(include_workflow_history=True))

    out_file = tmp_path / "report.html"
    exporter = HtmlReportExporter()
    exporter.export(report, out_file)

    assert out_file.exists()
    html = out_file.read_text()
    assert "MemSentry Forensic Report" in html
    assert "RPT-123" in html
    assert evidence.sha256 in html
    assert "Created test evidence" in html


def test_missing_case(registered_db):
    db, case, evidence = registered_db
    service = ReportService(
        CaseRepository(db),
        EvidenceRepository(db),
        AnalysisRunRepository(db),
        PluginRunRepository(db),
        FindingRepository(db),
        ArtifactRepository(db),
        WorkflowRepository(db),
    )

    with pytest.raises(ValueError, match="not found"):
        service.aggregate_report_data(uuid4(), ReportOptions())
