"""Synthetic Windows schemas and database integration; no live telemetry required."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest

from memsentry.correlation import CorrelationEngine
from memsentry.models.analysis_run import AnalysisRunCreate, HostOS
from memsentry.models.artifact import Artifact
from memsentry.models.case import CaseCreate
from memsentry.models.evidence import EvidenceCreate
from memsentry.storage.database import Database
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.finding_evidence_repository import FindingEvidenceRepository
from memsentry.storage.repositories.finding_repository import FindingRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.telemetry import (
    TelemetryError,
    TelemetryImportService,
    parse_edr_record,
    parse_windows_xml,
)

GUID = "11111111-1111-4111-8111-111111111111"


def xml_event(
    event_id,
    *,
    provider="Microsoft-Windows-Sysmon",
    channel="Microsoft-Windows-Sysmon/Operational",
    data="",
    user_data="",
    time="2026-01-01T05:30:00.1234567+05:30",
):
    return f'''<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>
    <Provider Name="{provider}"/><EventID>{event_id}</EventID><EventRecordID>123</EventRecordID>
    <TimeCreated SystemTime="{time}"/><Channel>{channel}</Channel><Computer>TEST-HOST</Computer>
    <Execution ProcessID="999"/></System><EventData>{data}</EventData>{user_data}</Event>'''


def parse(xml):
    return parse_windows_xml(xml, uuid4(), uuid4(), acquisition_id="synthetic-scope")


@pytest.mark.parametrize(
    ("event_id", "kind"),
    [
        (1, "process"),
        (8, "remote_thread"),
        (10, "process_access"),
        (11, "file_creation"),
        (25, "process_tampering"),
    ],
)
def test_sysmon_provider_scoped_schema(event_id, kind):
    xml = xml_event(
        event_id,
        data=f'<Data Name="ProcessGuid">{{{GUID}}}</Data><Data Name="ProcessId">10</Data><Data Name="SourceProcessId">10</Data><Data Name="SourceProcessGUID">{{{GUID}}}</Data><Data Name="TargetProcessId">20</Data><Data Name="GrantedAccess">0x1010</Data><Data Name="TargetImage">C:\\Windows\\System32\\lsass.exe</Data>',
    )
    artifact = parse(xml)
    assert artifact.artifact_type == kind
    assert artifact.pid == 10
    normalized = artifact.original_data["normalized"]
    assert normalized["timestamp"] == "2026-01-01T00:00:00.123456+00:00"
    assert normalized["original_timestamp"].endswith("+05:30")
    assert normalized["timestamp_precision"] == 1e-7
    assert artifact.original_data["xml"] == xml
    if event_id == 10:
        assert normalized["target_name"] == "lsass.exe"


@pytest.mark.parametrize("event_id", [4624, 4625, 4672, 4688])
def test_security_events(event_id):
    xml = xml_event(
        event_id,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        data='<Data Name="NewProcessId">0x2a</Data><Data Name="ProcessId">0x12</Data><Data Name="NewProcessName">C:\\Windows\\test.exe</Data><Data Name="TargetLogonId">0x456</Data><Data Name="SubjectLogonId">0x123</Data>',
    )
    artifact = parse(xml)
    assert artifact.artifact_type == ("process" if event_id == 4688 else "authentication_event")
    if event_id == 4688:
        assert artifact.pid == 42
        assert artifact.original_data["normalized"]["ppid"] == 18
    else:
        assert artifact.pid is None  # System/Execution PID is the logging service, not the subject.


def test_1102_userdata_and_wrong_provider_are_not_confused():
    data = '<UserData><LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog"><SubjectLogonId>0x123</SubjectLogonId><SubjectUserName>test</SubjectUserName></LogFileCleared></UserData>'
    artifact = parse(
        xml_event(1102, provider="Microsoft-Windows-Eventlog", channel="Security", user_data=data)
    )
    assert artifact.original_data["normalized"]["logon_id"] == "0x123"
    wrong = parse(xml_event(1, provider="Microsoft-Windows-Security-Auditing", channel="Security"))
    assert wrong.artifact_type == "windows_event"


def test_incomplete_records_and_missing_timezone():
    artifact = parse("<Event><System><EventID>10</EventID></System></Event>")
    assert artifact.artifact_type == "windows_event"
    assert artifact.pid is None
    assert artifact.provenance["warnings"]
    assert (
        parse(xml_event(1, time="2026-01-01T12:00:00")).original_data["normalized"]["timestamp"]
        is None
    )
    with pytest.raises(TelemetryError, match="Unsafe"):
        parse('<!DOCTYPE event [<!ENTITY foo "bar">]><Event/>')
    with pytest.raises(TelemetryError, match="Malformed"):
        parse("<broken")


def test_edr_preserves_source_and_rejects_invented_schema():
    source = {
        "schema_version": 1,
        "artifact_type": "memory_protection_transition",
        "normalized_data": {
            "pid": 10,
            "timestamp": "2026-01-01T00:00:00Z",
            "old_protection": "rw-",
            "new_protection": "r-x",
        },
    }
    artifact = parse_edr_record(source, uuid4(), uuid4(), acquisition_id="capture")
    assert artifact.original_data["source_record"] == source
    assert "acquisition_id" not in source["normalized_data"]
    with pytest.raises(TelemetryError):
        parse_edr_record(
            {**source, "schema_version": 2}, uuid4(), uuid4(), acquisition_id="capture"
        )
    with pytest.raises(TelemetryError, match="boolean"):
        parse_edr_record(
            {**source, "normalized_data": {"dump_validated": "true"}},
            uuid4(),
            uuid4(),
            acquisition_id="capture",
        )


@pytest.fixture
def registered(tmp_path):
    db = Database(tmp_path / "telemetry.sqlite3")
    db.initialize()
    dump = tmp_path / "synthetic.mem"
    dump.write_bytes(b"SYNTHETIC inert evidence bytes")
    case = CaseRepository(db).create(CaseCreate(case_number="TELEMETRY", name="Synthetic"))
    evidence = EvidenceRepository(db).create(
        EvidenceCreate(
            case_id=case.id,
            original_filename=dump.name,
            file_path=dump,
            file_size_bytes=dump.stat().st_size,
            sha256=hashlib.sha256(dump.read_bytes()).hexdigest(),
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
    return db, run, dump


def test_import_persist_correlate_findings_and_evidence(registered, tmp_path):
    db, run, dump = registered
    dump_hash = hashlib.sha256(dump.read_bytes()).hexdigest()
    source = tmp_path / "synthetic.jsonl"
    records = [
        {
            "schema_version": 1,
            "artifact_type": kind,
            "source_record_id": i,
            "normalized_data": {
                "pid": 10,
                "process_guid": GUID,
                "host_id": "host",
                "timestamp": "2026-01-01T00:00:00Z",
                **data,
            },
        }
        for i, (kind, data) in enumerate(
            [
                (
                    "memory_region",
                    {"private": True, "protection": "rwx", "start": 4096, "end": 8192},
                ),
                ("thread", {"start_address": 5000}),
                ("network_connection", {"remote_address": "192.0.2.1"}),
            ]
        )
    ]
    source.write_text("\n".join(json.dumps(record) for record in records))
    source_hash = hashlib.sha256(source.read_bytes()).hexdigest()
    persisted = TelemetryImportService(db).import_file(
        source, run.id, acquisition_id="capture", format="edr_jsonl"
    )
    loaded = ArtifactRepository(db).list_by_analysis_run(run.id)
    assert len(loaded) == len(persisted) == 3
    result = CorrelationEngine().correlate(loaded, run.id)
    assert "MS-R012" in {f.rule_id for f in result.findings}
    by_id = {a.id: a for a in loaded}
    findings = FindingRepository(db).create_many_with_evidence(
        [
            (finding, [by_id[key] for key in ids])
            for finding, ids in zip(result.findings, result.finding_artifact_ids, strict=True)
        ]
    )
    for finding in findings:
        assert FindingRepository(db).get_by_id(finding.id) == finding
        assert finding.id in {item.finding_id for item in result.findings}
        links = FindingEvidenceRepository(db).list_by_finding(finding.id)
        assert links
        assert all(link.source_reference in {str(key) for key in by_id} for link in links)
        assert any("correlation_details" in link.supporting_data for link in links)
    plugin = PluginRunRepository(db).list_by_analysis_run(run.id)[0]
    assert plugin.raw_output_sha256 == source_hash
    assert plugin.status == "completed"
    assert hashlib.sha256(dump.read_bytes()).hexdigest() == dump_hash
    assert hashlib.sha256(source.read_bytes()).hexdigest() == source_hash


def test_failed_import_is_audited_without_partial_artifacts(registered, tmp_path):
    db, run, _ = registered
    source = tmp_path / "bad.jsonl"
    source.write_text(
        '{"schema_version": 1, "artifact_type": "process", "normalized_data": {"pid": 1}}\nINVALID'
    )
    with pytest.raises(TelemetryError, match="line 2"):
        TelemetryImportService(db).import_file(
            source, run.id, acquisition_id="capture", format="edr_jsonl"
        )
    assert not ArtifactRepository(db).list_by_analysis_run(run.id)
    assert PluginRunRepository(db).list_by_analysis_run(run.id)[0].status == "failed"


def test_changed_source_fails_integrity_gate(registered, tmp_path, monkeypatch):
    db, run, _ = registered
    source = tmp_path / "empty.jsonl"
    source.write_text("")
    service = TelemetryImportService(db)
    hashes = iter(["a" * 64, "b" * 64])
    monkeypatch.setattr(service, "_hash", lambda path: next(hashes))
    with pytest.raises(TelemetryError, match="SHA-256 changed"):
        service.import_file(source, run.id, acquisition_id="capture", format="edr_jsonl")
    assert not ArtifactRepository(db).list_by_analysis_run(run.id)


def test_missing_evtx_dependency_is_explicit(registered, tmp_path, monkeypatch):
    db, run, _ = registered
    source = tmp_path / "synthetic.evtx"
    source.write_bytes(b"SYNTHETIC")

    def missing(name):
        raise ImportError("optional dependency missing")

    monkeypatch.setattr("memsentry.telemetry.service.importlib.import_module", missing)
    with pytest.raises(TelemetryError, match="optional python-evtx"):
        TelemetryImportService(db).import_file(
            source, run.id, acquisition_id="capture", format="evtx"
        )


def test_import_xml_clear_sequence_uses_real_source_references(registered, tmp_path):
    db, run, _ = registered
    source = tmp_path / "events.xml"
    privilege = xml_event(
        4672,
        provider="Microsoft-Windows-Security-Auditing",
        channel="Security",
        time="2026-01-01T00:00:00Z",
        data='<Data Name="SubjectLogonId">0x123</Data>',
    )
    cleared = xml_event(
        1102,
        provider="Microsoft-Windows-Eventlog",
        channel="Security",
        time="2026-01-01T00:01:00Z",
        user_data="<UserData><LogFileCleared><SubjectLogonId>0x123</SubjectLogonId></LogFileCleared></UserData>",
    )
    source.write_text(f"<Events>{privilege}{cleared}</Events>")
    loaded = TelemetryImportService(db).import_file(
        source, run.id, acquisition_id="capture", format="xml"
    )
    result = CorrelationEngine().correlate(loaded, run.id)
    assert {f.rule_id for f in result.findings} == {"MS-R009"}
    assert set(result.finding_artifact_ids[0]) == {a.id for a in loaded}


def test_legacy_persisted_model_still_accepts_empty_provenance():
    artifact = Artifact(
        id=uuid4(),
        analysis_run_id=uuid4(),
        plugin_run_id=uuid4(),
        artifact_type="process",
        pid=10,
        original_data={"normalized": {"process_name": "legacy.exe", "ppid": 1}},
        provenance={},
        created_at=datetime.now(UTC),
    )
    assert (
        CorrelationEngine()
        .correlate([artifact], artifact.analysis_run_id)
        .process_contexts[10]
        .process_name
        == "legacy.exe"
    )
