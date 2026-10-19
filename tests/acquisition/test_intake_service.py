import hashlib
import json
import shutil
from dataclasses import replace
from threading import Event
from types import SimpleNamespace

import pytest

from memsentry.app.intake_service import IntakeCancelled, IntakeRequest, IntakeService
from memsentry.app.workflow_service import WorkflowService
from memsentry.models.evidence import EvidenceOS
from memsentry.storage.database import Database
from memsentry.storage.repositories.evidence_repository import EvidenceRepository


@pytest.fixture
def request_data(tmp_path):
    source = tmp_path / "sample.mem"
    source.write_bytes(b"synthetic memory only" * 1024)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    return IntakeRequest(workspace, "TEST-001", "Test case", source, EvidenceOS.WINDOWS)


def test_import_is_read_only_and_persists_verified_evidence(request_data):
    before = request_data.source.read_bytes()
    updates = []
    result = IntakeService().run(request_data, lambda *args: updates.append(args), Event())
    assert request_data.source.read_bytes() == before
    assert result.evidence.sha256 == hashlib.sha256(before).hexdigest()
    stored = EvidenceRepository(Database(result.database_path)).get_by_id(result.evidence.id)
    assert stored.file_path == request_data.source
    assert stored.integrity_status == "verified"
    records = [json.loads(line) for line in result.audit_path.read_text().splitlines()]
    assert [record["action"] for record in records] == [
        "started",
        "baseline",
        "verified",
        "registered",
    ]
    assert updates[-1][1] == 100


def test_changed_image_is_not_registered(request_data):
    def progress(stage, value):
        if stage == "Verifying evidence SHA-256" and value == 0:
            request_data.source.write_bytes(b"changed test fixture")

    with pytest.raises(ValueError, match="changed during intake"):
        IntakeService().run(request_data, progress, Event())
    audit = next(request_data.workspace.rglob("audit.jsonl"))
    assert "integrity_failed" in audit.read_text()


def test_cancel_during_hashing_preserves_source(request_data):
    cancel = Event()
    original = request_data.source.read_bytes()
    with pytest.raises(IntakeCancelled):
        IntakeService().run(request_data, lambda *_: cancel.set(), cancel)
    assert request_data.source.read_bytes() == original
    assert "cancelled" in next(request_data.workspace.rglob("audit.jsonl")).read_text()


def test_case_name_conflict_is_not_silently_reused(request_data):
    IntakeService().run(request_data, lambda *_: None, Event())
    with pytest.raises(ValueError, match="already belongs"):
        IntakeService().run(
            replace(request_data, case_name="Different case"), lambda *_: None, Event()
        )


def test_capture_registers_only_after_hash_verification(request_data, monkeypatch):
    from datetime import UTC, datetime

    from memsentry.acquisition.adapters.base import AcquisitionResult
    from memsentry.acquisition.adapters.linuxDumpManager import LinuxAvmlAdapter
    from memsentry.acquisition.dump_manager import DumpManager

    monkeypatch.setattr(LinuxAvmlAdapter, "elevation_required", property(lambda _: False))

    monkeypatch.setattr("memsentry.app.intake_service.platform.system", lambda: "Linux")
    monkeypatch.setattr(
        "memsentry.app.intake_service.LinuxAvmlAdapter.check_requirements", lambda _: None
    )
    monkeypatch.setattr(
        "memsentry.app.intake_service.psutil.virtual_memory",
        lambda: type("Memory", (), {"total": 1024})(),
    )

    def capture(self, directory, filename, callback):
        path = directory / filename
        path.write_bytes(b"fake capture")
        # Simulate a large capture's per-MiB callbacks without creating a real dump.
        callback(24_576, 10.0)
        for written in range(24_577):
            callback(written, None)
        now = datetime.now(UTC)
        return AcquisitionResult(
            path,
            path.stat().st_size,
            hashlib.sha256(path.read_bytes()).hexdigest(),
            "fake",
            ("fake", str(path)),
            now,
            now,
        )

    monkeypatch.setattr(DumpManager, "capture_live", capture)
    updates = []
    result = IntakeService().run(
        replace(request_data, source=None, tool_path=request_data.source),
        lambda *args: updates.append(args), Event()
    )
    assert result.evidence.evidence_os == EvidenceOS.LINUX
    assert result.evidence.file_path.suffix == ".lime"
    with Database(result.database_path).connection() as connection:
        row = connection.execute("SELECT file_path, path_base FROM evidence").fetchone()
    assert row["path_base"] == "case"
    assert row["file_path"].startswith("intake/")
    hashing = [value for stage, value in updates if stage == "Hashing captured image"]
    assert hashing == list(range(100))


def test_reject_database_as_evidence(request_data):
    path = request_data.workspace / "memsentry.sqlite3"
    path.write_bytes(b"not evidence")
    with pytest.raises(ValueError, match="conflicts"):
        IntakeService().run(replace(request_data, source=path), lambda *_: None, Event())
    assert path.read_bytes() == b"not evidence"


def test_reimport_does_not_replace_registered_baseline(request_data):
    service = IntakeService()
    result = service.run(request_data, lambda *_: None, Event())
    same = service.run(request_data, lambda *_: None, Event())
    assert same.evidence.id == result.evidence.id
    request_data.source.write_bytes(b"different fixture data")
    with pytest.raises(ValueError, match="registered hash"):
        service.run(request_data, lambda *_: None, Event())
    stored = EvidenceRepository(Database(result.database_path)).get_by_id(result.evidence.id)
    assert stored.sha256 == result.evidence.sha256
    assert stored.integrity_status == "modified"


def test_cancel_elevated_capture_waits_then_skips_registration(request_data, monkeypatch):
    from memsentry.acquisition.adapters.linuxDumpManager import LinuxAvmlAdapter
    from memsentry.acquisition.dump_manager import DumpManager

    cancel = Event()
    monkeypatch.setattr("memsentry.app.intake_service.platform.system", lambda: "Linux")
    monkeypatch.setattr(LinuxAvmlAdapter, "check_requirements", lambda _: None)
    monkeypatch.setattr(LinuxAvmlAdapter, "elevation_required", property(lambda _: True))
    monkeypatch.setattr(
        "memsentry.app.intake_service.psutil.virtual_memory",
        lambda: type("Memory", (), {"total": 1024})(),
    )
    updates = []

    def capture(self, directory, filename, callback):
        cancel.set()
        callback(100, 1.0)  # Must not try to kill the elevated tool.
        callback(200, 2.0)
        callback(200, None)  # Capture ended; hashing may now honour cancellation.
        pytest.fail("Cancelled capture must not complete hashing")

    monkeypatch.setattr(DumpManager, "capture_live", capture)
    with pytest.raises(IntakeCancelled):
        IntakeService().run(
            replace(request_data, source=None, tool_path=request_data.source),
            lambda *args: updates.append(args),
            cancel,
        )
    assert any("Cancellation pending" in message for message, _ in updates)
    audit = next(request_data.workspace.rglob("audit.jsonl")).read_text()
    assert '"action": "cancelled"' in audit
    assert '"action": "registered"' not in audit


def test_copy_is_verified_and_accessible_after_workspace_moves(request_data, tmp_path):
    original = request_data.source.read_bytes()
    original_stat = request_data.source.stat()
    result = IntakeService().run(
        replace(request_data, copy_into_case=True), lambda *_: None, Event()
    )
    copied = result.evidence.file_path
    case_dir = request_data.workspace / "cases" / str(result.evidence.case_id)
    assert copied.is_relative_to(case_dir / "evidence")
    assert copied.name == request_data.source.name
    assert copied.read_bytes() == original
    assert request_data.source.read_bytes() == original
    assert request_data.source.stat().st_mtime_ns == original_stat.st_mtime_ns
    database = Database(result.database_path)
    with database.connection() as connection:
        row = connection.execute("SELECT file_path, path_base FROM evidence").fetchone()
    assert row["path_base"] == "case"
    assert row["file_path"] == copied.relative_to(case_dir).as_posix()
    records = [json.loads(line) for line in result.audit_path.read_text().splitlines()]
    assert {record["action"] for record in records} >= {
        "copy_space_checked", "baseline", "copy_started", "copy_verified", "registered"
    }
    moved = tmp_path / "moved-workspace"
    shutil.move(str(request_data.workspace), moved)
    request_data.source.rename(tmp_path / "original-offline.mem")
    relocated_db = Database(moved / "memsentry.sqlite3")
    evidence = EvidenceRepository(relocated_db).get_by_id(result.evidence.id)
    assert evidence.file_path == moved / copied.relative_to(request_data.workspace)
    assert evidence.file_path.read_bytes() == original
    WorkflowService(relocated_db).verify(evidence, None, "verify", "after")


def test_copy_low_space_stops_before_hashing(request_data, monkeypatch):
    monkeypatch.setattr(
        "memsentry.app.evidence_copy.shutil.disk_usage", lambda _: SimpleNamespace(free=1)
    )
    with pytest.raises(ValueError, match="Insufficient free space"):
        IntakeService().run(
            replace(request_data, copy_into_case=True),
            lambda *_: pytest.fail("Must reject insufficient space before reading evidence"),
            Event(),
        )
    assert not list(request_data.workspace.rglob("*.partial"))
    audit = next(request_data.workspace.rglob("audit.jsonl")).read_text()
    assert '"action": "registered"' not in audit


@pytest.mark.parametrize("stage", [
    "Copying evidence into case",
    "Verifying copied evidence SHA-256",
    "Verifying evidence SHA-256",
])
def test_cancel_copy_removes_only_new_files(request_data, stage):
    cancel = Event()
    original = request_data.source.read_bytes()

    def progress(message, value):
        if message == stage and (stage != "Copying evidence into case" or value > 0):
            cancel.set()

    with pytest.raises(IntakeCancelled):
        IntakeService().run(replace(request_data, copy_into_case=True), progress, cancel)
    assert request_data.source.read_bytes() == original
    assert not list(request_data.workspace.rglob("*.partial"))
    assert not list(request_data.workspace.rglob(request_data.source.name))
    assert '"action": "copy_removed"' in next(request_data.workspace.rglob("audit.jsonl")).read_text()


@pytest.mark.parametrize("change_copy", [False, True])
def test_copy_rejects_changed_source_or_corrupted_destination(request_data, change_copy):
    original = request_data.source.read_bytes()

    def progress(stage, value):
        if stage == "Verifying copied evidence SHA-256" and value == 0:
            target = next(request_data.workspace.rglob("*.partial")) if change_copy else request_data.source
            target.write_bytes(b"X" * len(original))

    with pytest.raises(ValueError, match=r"does not match|changed during intake"):
        IntakeService().run(replace(request_data, copy_into_case=True), progress, Event())
    assert not list(request_data.workspace.rglob("*.partial"))
    assert not list(request_data.workspace.rglob(request_data.source.name))
    if change_copy:
        assert request_data.source.read_bytes() == original


def test_copy_write_failure_cleans_partial_image(request_data, monkeypatch):
    import errno

    original = request_data.source.read_bytes()

    def fail_copy(source, destination, *args):
        destination.write_bytes(b"partial")
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr("memsentry.app.intake_service.copy_image", fail_copy)
    with pytest.raises(OSError, match="No space left"):
        IntakeService().run(replace(request_data, copy_into_case=True), lambda *_: None, Event())
    assert request_data.source.read_bytes() == original
    assert not list(request_data.workspace.rglob("*.partial"))


def test_repeat_copy_never_overwrites_existing_evidence(request_data):
    request = replace(request_data, copy_into_case=True)
    first = IntakeService().run(request, lambda *_: None, Event())
    first_bytes = first.evidence.file_path.read_bytes()
    second = IntakeService().run(request, lambda *_: None, Event())
    assert first.evidence.file_path != second.evidence.file_path
    assert first.evidence.file_path.read_bytes() == first_bytes
    assert second.evidence.sha256 == first.evidence.sha256


def test_copy_cannot_replace_a_previously_registered_baseline(request_data):
    first = IntakeService().run(request_data, lambda *_: None, Event())
    request_data.source.write_bytes(b"changed synthetic evidence")
    with pytest.raises(ValueError, match="registered hash"):
        IntakeService().run(replace(request_data, copy_into_case=True), lambda *_: None, Event())
    repository = EvidenceRepository(Database(first.database_path))
    assert len(repository.list_by_case(first.evidence.case_id)) == 1
    assert repository.get_by_id(first.evidence.id).integrity_status == "modified"
    assert not list(request_data.workspace.rglob("*.partial"))


def test_registration_failure_removes_verified_copy(request_data, monkeypatch):
    def fail_registration(*args, **kwargs):
        raise RuntimeError("Database registration failed")

    monkeypatch.setattr(EvidenceRepository, "create", fail_registration)
    with pytest.raises(RuntimeError, match="Database registration failed"):
        IntakeService().run(replace(request_data, copy_into_case=True), lambda *_: None, Event())
    assert not list(request_data.workspace.rglob(request_data.source.name))
    assert request_data.source.is_file()


def test_post_registration_failure_keeps_registered_copy(request_data, monkeypatch):
    def fail_record(*args, **kwargs):
        raise RuntimeError("Workflow recording failed")

    monkeypatch.setattr("memsentry.app.intake_service.WorkflowRepository.record", fail_record)
    with pytest.raises(RuntimeError, match="Workflow recording failed"):
        IntakeService().run(replace(request_data, copy_into_case=True), lambda *_: None, Event())
    case = IntakeService.list_cases(request_data.workspace)[0]
    evidence = EvidenceRepository(Database(request_data.workspace / "memsentry.sqlite3")).list_by_case(case.id)
    assert len(evidence) == 1
    assert evidence[0].file_path.read_bytes() == request_data.source.read_bytes()


def test_copy_changed_after_its_hash_is_rejected(request_data):
    def progress(stage, value):
        if stage == "Verifying evidence SHA-256" and value == 0:
            copied = next(request_data.workspace.rglob("*.partial"))
            copied.write_bytes(b"changed copy")

    with pytest.raises(ValueError, match="Copied evidence changed during verification"):
        IntakeService().run(replace(request_data, copy_into_case=True), progress, Event())
    assert not list(request_data.workspace.rglob("*.partial"))


def test_space_is_rechecked_after_baseline_hash(request_data, monkeypatch):
    def progress(stage, value):
        if stage == "Calculating SHA-256 baseline":
            monkeypatch.setattr(
                "memsentry.app.evidence_copy.shutil.disk_usage", lambda _: SimpleNamespace(free=0)
            )

    with pytest.raises(ValueError, match="Insufficient free space"):
        IntakeService().run(replace(request_data, copy_into_case=True), progress, Event())
    assert not list(request_data.workspace.rglob("*.partial"))
