import hashlib
import json
from dataclasses import replace
from threading import Event

import pytest

from memsentry.app.intake_service import IntakeCancelled, IntakeRequest, IntakeService
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
