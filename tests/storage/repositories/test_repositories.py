from __future__ import annotations

from pathlib import Path
from uuid import uuid4

import pytest

from memsentry.models.analysis_run import AnalysisRunCreate, AnalysisRunStatus, HostOS
from memsentry.models.case import CaseCreate, CaseStatus, CaseUpdate
from memsentry.models.evidence import EvidenceCreate, EvidenceOS, IntegrityStatus
from memsentry.models.finding import FindingCreate, FindingSeverity
from memsentry.models.finding_evidence import FindingEvidenceCreate
from memsentry.models.plugin_run import PluginRunCreate, PluginRunStatus
from memsentry.storage.database import Database
from memsentry.storage.repositories.analysis_run_repository import (
    AnalysisRunNotFoundError,
    AnalysisRunRepository,
)
from memsentry.storage.repositories.case_repository import (
    CaseNotFoundError,
    CaseRepository,
    DuplicateCaseNumberError,
)
from memsentry.storage.repositories.evidence_repository import (
    EvidenceNotFoundError,
    EvidenceRepository,
)
from memsentry.storage.repositories.finding_evidence_repository import (
    FindingEvidenceRepository,
)
from memsentry.storage.repositories.finding_repository import FindingRepository
from memsentry.storage.repositories.plugin_run_repository import (
    PluginRunNotFoundError,
    PluginRunRepository,
)


@pytest.fixture
def db(tmp_path: Path) -> Database:
    db_file = tmp_path / "test_memsentry.db"
    database = Database(db_file)
    database.initialize()
    return database


def test_case_repository_crud_and_status(db: Database) -> None:
    repo = CaseRepository(db)

    # 1. Create case
    case_create = CaseCreate(
        case_number="CASE-2026-001",
        name="Test Incident Investigation",
        description="Initial test case",
    )
    case = repo.create(case_create)
    assert case.case_number == "CASE-2026-001"
    assert case.name == "Test Incident Investigation"
    assert case.status == CaseStatus.OPEN

    # 2. Duplicate case_number error
    with pytest.raises(DuplicateCaseNumberError):
        repo.create(
            CaseCreate(
                case_number="CASE-2026-001",
                name="Duplicate Case",
            )
        )

    # 3. Get by ID
    by_id = repo.get_by_id(case.id)
    assert by_id is not None
    assert by_id.id == case.id

    # 4. Get by case_number
    by_num = repo.get_by_case_number("CASE-2026-001")
    assert by_num is not None
    assert by_num.id == case.id

    # 5. List all
    all_cases = repo.list_all()
    assert len(all_cases) == 1
    assert all_cases[0].id == case.id

    # 6. Update details
    updated = repo.update_details(
        case.id,
        CaseUpdate(name="Updated Case Name", description="Updated description"),
    )
    assert updated.name == "Updated Case Name"
    assert updated.description == "Updated description"

    # 7. Change status
    archived = repo.change_status(case.id, CaseStatus.ARCHIVED)
    assert archived.status == CaseStatus.ARCHIVED

    # 8. Not found exceptions
    random_id = uuid4()
    assert repo.get_by_id(random_id) is None
    assert repo.get_by_case_number("NONEXISTENT") is None
    with pytest.raises(CaseNotFoundError):
        repo.update_details(random_id, CaseUpdate(name="X"))
    with pytest.raises(CaseNotFoundError):
        repo.change_status(random_id, CaseStatus.CLOSED)


def test_evidence_repository(db: Database) -> None:
    case_repo = CaseRepository(db)
    evidence_repo = EvidenceRepository(db)

    case = case_repo.create(CaseCreate(case_number="C-01", name="Case 1"))

    # 1. Create evidence
    ev_create = EvidenceCreate(
        case_id=case.id,
        original_filename="memdump.raw",
        file_path=Path("/forensics/memdump.raw"),
        file_size_bytes=4294967296,
        sha256="c" * 64,
        evidence_os=None,
    )
    evidence = evidence_repo.create(ev_create)
    assert evidence.case_id == case.id
    assert evidence.original_filename == "memdump.raw"
    assert evidence.integrity_status == IntegrityStatus.VERIFIED
    assert evidence.evidence_os is None

    # 2. Get by ID & list by case
    retrieved = evidence_repo.get_by_id(evidence.id)
    assert retrieved is not None
    assert retrieved.sha256 == "c" * 64

    case_evidences = evidence_repo.list_by_case(case.id)
    assert len(case_evidences) == 1

    # 3. Set evidence OS
    updated_os = evidence_repo.set_evidence_os(evidence.id, EvidenceOS.WINDOWS)
    assert updated_os.evidence_os == EvidenceOS.WINDOWS

    # 4. Update integrity status
    updated_integ = evidence_repo.update_integrity_status(
        evidence.id, IntegrityStatus.MODIFIED
    )
    assert updated_integ.integrity_status == IntegrityStatus.MODIFIED

    # 5. Not found exceptions
    random_id = uuid4()
    with pytest.raises(EvidenceNotFoundError):
        evidence_repo.set_evidence_os(random_id, EvidenceOS.LINUX)
    with pytest.raises(EvidenceNotFoundError):
        evidence_repo.update_integrity_status(random_id, IntegrityStatus.UNAVAILABLE)


def test_analysis_run_repository(db: Database) -> None:
    case = CaseRepository(db).create(CaseCreate(case_number="C-02", name="Case 2"))
    evidence = EvidenceRepository(db).create(
        EvidenceCreate(
            case_id=case.id,
            original_filename="mem.raw",
            file_path=Path("/tmp/mem.raw"),
            file_size_bytes=1000,
            sha256="d" * 64,
        )
    )

    repo = AnalysisRunRepository(db)

    # 1. Create
    run_create = AnalysisRunCreate(
        evidence_id=evidence.id,
        application_version="0.1.0",
        volatility_version="2.4.1",
        host_os=HostOS.LINUX,
    )
    run = repo.create(run_create)
    assert run.status == AnalysisRunStatus.PENDING
    assert run.host_os == HostOS.LINUX
    assert run.started_at is None

    # 2. Mark running
    running = repo.mark_running(run.id)
    assert running.status == AnalysisRunStatus.RUNNING
    assert running.started_at is not None

    # 3. Mark completed
    completed = repo.mark_completed(run.id)
    assert completed.status == AnalysisRunStatus.COMPLETED
    assert completed.completed_at is not None

    # 4. List by evidence
    runs = repo.list_by_evidence(evidence.id)
    assert len(runs) == 1

    # 5. Mark completed with errors, failed, cancelled test on new runs
    r2 = repo.create(run_create)
    r2_err = repo.mark_completed_with_errors(r2.id, "Minor warning")
    assert r2_err.status == AnalysisRunStatus.COMPLETED_WITH_ERRORS
    assert r2_err.error_message == "Minor warning"

    r3 = repo.create(run_create)
    r3_fail = repo.mark_failed(r3.id, "Fatal volatility crash")
    assert r3_fail.status == AnalysisRunStatus.FAILED
    assert r3_fail.error_message == "Fatal volatility crash"

    r4 = repo.create(run_create)
    r4_cancel = repo.mark_cancelled(r4.id)
    assert r4_cancel.status == AnalysisRunStatus.CANCELLED

    with pytest.raises(AnalysisRunNotFoundError):
        repo.mark_running(uuid4())


def test_plugin_run_repository(db: Database) -> None:
    case = CaseRepository(db).create(CaseCreate(case_number="C-03", name="Case 3"))
    evidence = EvidenceRepository(db).create(
        EvidenceCreate(
            case_id=case.id,
            original_filename="dump.raw",
            file_path=Path("/tmp/dump.raw"),
            file_size_bytes=1000,
            sha256="e" * 64,
        )
    )
    analysis_run = AnalysisRunRepository(db).create(
        AnalysisRunCreate(
            evidence_id=evidence.id,
            application_version="0.1.0",
            volatility_version="2.4.1",
            host_os=HostOS.LINUX,
        )
    )

    repo = PluginRunRepository(db)

    # 1. Create plugin run with config dictionary
    config = {"pid": 1234, "verbose": True}
    p_create = PluginRunCreate(
        analysis_run_id=analysis_run.id,
        plugin_name="windows.pslist.PsList",
        configuration=config,
    )
    plugin_run = repo.create(p_create)
    assert plugin_run.status == PluginRunStatus.PENDING
    assert plugin_run.configuration == config

    # 2. Mark running
    p_running = repo.mark_running(plugin_run.id)
    assert p_running.status == PluginRunStatus.RUNNING
    assert p_running.started_at is not None

    # 3. Mark completed with raw output details
    out_path = Path("/tmp/outputs/pslist.json")
    out_hash = "f" * 64
    p_completed = repo.mark_completed(plugin_run.id, out_path, out_hash)
    assert p_completed.status == PluginRunStatus.COMPLETED
    assert p_completed.raw_output_path == out_path
    assert p_completed.raw_output_sha256 == out_hash

    # 4. List by analysis run
    plugin_runs = repo.list_by_analysis_run(analysis_run.id)
    assert len(plugin_runs) == 1
    assert plugin_runs[0].configuration == config

    # 5. Failed and cancelled checks
    p2 = repo.create(p_create)
    p2_failed = repo.mark_failed(p2.id, "Symbol file missing")
    assert p2_failed.status == PluginRunStatus.FAILED

    p3 = repo.create(p_create)
    p3_cancelled = repo.mark_cancelled(p3.id)
    assert p3_cancelled.status == PluginRunStatus.CANCELLED

    with pytest.raises(PluginRunNotFoundError):
        repo.mark_running(uuid4())


def test_finding_repository(db: Database) -> None:
    case = CaseRepository(db).create(CaseCreate(case_number="C-04", name="Case 4"))
    evidence = EvidenceRepository(db).create(
        EvidenceCreate(
            case_id=case.id,
            original_filename="dump.raw",
            file_path=Path("/tmp/dump.raw"),
            file_size_bytes=1000,
            sha256="1" * 64,
        )
    )
    analysis_run = AnalysisRunRepository(db).create(
        AnalysisRunCreate(
            evidence_id=evidence.id,
            application_version="0.1.0",
            volatility_version="2.4.1",
            host_os=HostOS.LINUX,
        )
    )

    repo = FindingRepository(db)

    f_create = FindingCreate(
        analysis_run_id=analysis_run.id,
        rule_id="RULE-MAL-PROC",
        title="Unusual Process Hollowing",
        description="Process svchost.exe spawned without parent",
        severity=FindingSeverity.HIGH,
        confidence=0.9,
    )
    finding = repo.create(f_create)
    assert finding.rule_id == "RULE-MAL-PROC"
    assert finding.severity == FindingSeverity.HIGH
    assert finding.confidence == 0.9

    # Retrieve by ID
    retrieved = repo.get_by_id(finding.id)
    assert retrieved is not None
    assert retrieved.title == "Unusual Process Hollowing"

    # List by analysis run
    all_findings = repo.list_by_analysis_run(analysis_run.id)
    assert len(all_findings) == 1

    # List by severity
    high_findings = repo.list_by_severity(analysis_run.id, FindingSeverity.HIGH)
    assert len(high_findings) == 1

    low_findings = repo.list_by_severity(analysis_run.id, FindingSeverity.LOW)
    assert len(low_findings) == 0


def test_finding_evidence_repository(db: Database) -> None:
    case = CaseRepository(db).create(CaseCreate(case_number="C-05", name="Case 5"))
    evidence = EvidenceRepository(db).create(
        EvidenceCreate(
            case_id=case.id,
            original_filename="dump.raw",
            file_path=Path("/tmp/dump.raw"),
            file_size_bytes=1000,
            sha256="2" * 64,
        )
    )
    analysis_run = AnalysisRunRepository(db).create(
        AnalysisRunCreate(
            evidence_id=evidence.id,
            application_version="0.1.0",
            volatility_version="2.4.1",
            host_os=HostOS.LINUX,
        )
    )
    plugin_run = PluginRunRepository(db).create(
        PluginRunCreate(
            analysis_run_id=analysis_run.id,
            plugin_name="windows.pslist.PsList",
        )
    )
    finding = FindingRepository(db).create(
        FindingCreate(
            analysis_run_id=analysis_run.id,
            rule_id="RULE-01",
            title="Suspicious Process",
            description="Process detail",
            severity=FindingSeverity.MEDIUM,
        )
    )

    repo = FindingEvidenceRepository(db)

    supporting = {"pid": 4096, "ppid": 100, "name": "cmd.exe"}
    fe_create = FindingEvidenceCreate(
        finding_id=finding.id,
        plugin_run_id=plugin_run.id,
        artifact_type="process_list_row",
        source_reference="pslist offset 0x7e800",
        supporting_data=supporting,
        explanation="Cmd.exe spawned under unexpected parent",
    )

    fe = repo.create(fe_create)
    assert fe.finding_id == finding.id
    assert fe.plugin_run_id == plugin_run.id
    assert fe.supporting_data == supporting

    # Get by ID
    retrieved = repo.get_by_id(fe.id)
    assert retrieved is not None
    assert retrieved.explanation == "Cmd.exe spawned under unexpected parent"

    # List by finding
    ev_list = repo.list_by_finding(finding.id)
    assert len(ev_list) == 1
    assert ev_list[0].supporting_data["pid"] == 4096
