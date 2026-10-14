"""Read-only evidence intake with persisted case metadata and operation history."""

from __future__ import annotations

import hashlib
import json
import platform
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from threading import Event
from uuid import uuid4

import psutil

from memsentry.acquisition.adapters.base import DumpAdapter
from memsentry.acquisition.adapters.linuxDumpManager import LinuxAvmlAdapter
from memsentry.acquisition.adapters.windowsDumpManager import WindowsWinPmemAdapter
from memsentry.acquisition.dump_manager import DumpManager
from memsentry.models.case import Case, CaseCreate
from memsentry.models.evidence import Evidence, EvidenceCreate, EvidenceOS, IntegrityStatus
from memsentry.storage.database import Database
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.workflow_repository import WorkflowRepository


class IntakeCancelled(RuntimeError):
    """The operator cancelled before evidence registration."""


@dataclass(frozen=True)
class IntakeRequest:
    workspace: Path
    case_number: str
    case_name: str
    source: Path | None = None
    evidence_os: EvidenceOS | None = None
    tool_path: Path | None = None
    avml_modern: bool = True


@dataclass(frozen=True)
class IntakeResult:
    evidence: Evidence
    database_path: Path
    audit_path: Path


Progress = Callable[[str, int], None]


class IntakeService:
    """Called on a worker thread; connections are opened through repositories."""

    @staticmethod
    def list_cases(workspace: Path) -> list[Case]:
        path = workspace.expanduser().resolve() / "memsentry.sqlite3"
        return CaseRepository(Database(path)).list_all() if path.is_file() else []

    def run(self, request: IntakeRequest, progress: Progress, cancelled: Event) -> IntakeResult:
        last_progress: tuple[str, int] | None = None

        def report(stage: str, value: int) -> None:
            nonlocal last_progress
            update = (stage, value)
            # Chunk callbacks still check cancellation, but must not flood Qt's event queue.
            if update != last_progress:
                last_progress = update
                progress(stage, value)

        def check_cancel() -> None:
            if cancelled.is_set():
                raise IntakeCancelled(
                    "Cancelled. No evidence was registered; any capture is retained."
                )

        check_cancel()
        if not request.case_number.strip() or not request.case_name.strip():
            raise ValueError("Enter a case number and case name.")
        workspace = request.workspace.expanduser().resolve()
        if not workspace.is_dir():
            raise ValueError("Choose an existing writable workspace folder.")
        source = request.source.expanduser().resolve() if request.source else None
        if source is not None and (not source.is_file() or source.stat().st_size == 0):
            raise ValueError("Select a non-empty memory image file.")
        db_path = workspace / "memsentry.sqlite3"
        if source and any(
            path.exists() and source.samefile(path)
            for path in (db_path, Path(str(db_path) + "-wal"), Path(str(db_path) + "-shm"))
        ):
            raise ValueError("The selected evidence conflicts with the workspace database.")
        if source and (
            source == db_path
            or (
                source.name in {"memsentry.sqlite3-wal", "memsentry.sqlite3-shm"}
                and source.parent == workspace
            )
        ):
            raise ValueError("The selected evidence conflicts with the workspace database.")

        adapter: DumpAdapter | None = None
        if source is None:
            host = platform.system()
            if host == "Linux":
                adapter = LinuxAvmlAdapter(
                    request.tool_path, acquire_subcommand=request.avml_modern
                )
            elif host == "Windows":
                adapter = WindowsWinPmemAdapter(request.tool_path)
            else:
                raise ValueError("Live capture is currently available on Windows and Linux only.")
            adapter.check_requirements()
            if shutil.disk_usage(workspace).free < psutil.virtual_memory().total:
                raise ValueError("Insufficient free workspace space for the estimated RAM capture.")

        database = Database(db_path)
        database.initialize()
        cases = CaseRepository(database)
        case = cases.get_by_case_number(request.case_number.strip())
        if case:
            if case.status != "open":
                raise ValueError("This case is closed or archived. Choose an open case.")
            if case.name != request.case_name.strip():
                raise ValueError(
                    f"Case number already belongs to '{case.name}'. Use that name to add evidence."
                )
        else:
            case = cases.create(
                CaseCreate(case_number=request.case_number.strip(), name=request.case_name.strip())
            )
        case_dir = workspace / "cases" / str(case.id)
        case_dir.mkdir(parents=True, exist_ok=True)
        operation = case_dir / "intake" / str(uuid4())
        operation.mkdir(parents=True, mode=0o700)
        audit_path = operation / "audit.jsonl"

        def audit(action: str, **data: object) -> None:
            with audit_path.open("a", encoding="utf-8") as log:
                log.write(
                    json.dumps(
                        {
                            "time": datetime.now(UTC).isoformat(),
                            "action": action,
                            "case_id": str(case.id),
                            **data,
                        }
                    )
                    + "\n"
                )

        def hash_file(path: Path, stage: str) -> str:
            digest = hashlib.sha256()
            total = path.stat().st_size
            report(stage, 0)
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(4 * 1024 * 1024), b""):
                    check_cancel()
                    digest.update(chunk)
                    report(stage, min(99, int(stream.tell() * 100 / max(total, 1))))
            check_cancel()
            return digest.hexdigest()

        audit(
            "started",
            mode="import" if source else "capture",
            source=str(source) if source else None,
        )
        try:
            expected = None
            os_type = request.evidence_os
            if adapter:
                expected_size = psutil.virtual_memory().total
                captured_size = expected_size
                elevated = adapter.elevation_required

                def capture_progress(written: int, elapsed: float | None) -> None:
                    nonlocal captured_size
                    if elapsed is not None:
                        captured_size = max(written, 1)
                    # An unprivileged process cannot reliably terminate an elevated tool.
                    # Defer cancellation until capture returns or hashing starts.
                    if not elevated or elapsed is None:
                        check_cancel()
                    if elevated and cancelled.is_set():
                        report(
                            "Cancellation pending — waiting for elevated capture to finish", -1
                        )
                        return
                    stage = (
                        "Hashing captured image"
                        if elapsed is None
                        else "Capturing memory (estimated)"
                    )
                    if elevated and written == 0 and elapsed is not None:
                        report(
                            "Approve the system authentication prompt · waiting for capture", -1
                        )
                        return
                    report(
                        stage,
                        min(99, int(written * 100 / (
                            captured_size if elapsed is None else expected_size))),
                    )

                suffix = ".lime" if adapter.target_os == "linux" else ".raw"
                audit(
                    "capture_started",
                    tool=str(adapter.executable),
                    tool_sha256=hash_file(adapter.executable, "Hashing acquisition tool"),
                    elevation=("polkit" if adapter.target_os == "linux" else "uac")
                    if elevated
                    else "already_privileged",
                )
                check_cancel()
                if elevated:
                    report(
                        f"Approve the system authentication prompt · only {adapter.tool_name} is elevated",
                        -1,
                    )
                result = DumpManager(adapter).capture_live(
                    operation, "memory" + suffix, capture_progress
                )
                check_cancel()
                source = result.output_path
                expected = result.sha256
                os_type = EvidenceOS(adapter.target_os)
                audit("capture_completed", path=str(source), command=result.command)
            assert source is not None
            before = source.stat()
            baseline = expected or hash_file(source, "Calculating SHA-256 baseline")
            audit("baseline", sha256=baseline, path=str(source))
            verified = hash_file(source, "Verifying evidence SHA-256")
            after = source.stat()
            if baseline != verified or (before.st_size, before.st_mtime_ns, before.st_ino) != (
                after.st_size,
                after.st_mtime_ns,
                after.st_ino,
            ):
                audit("integrity_failed", expected=baseline, actual=verified)
                raise ValueError(
                    "Evidence changed during intake. Registration stopped; original hash retained in the audit log."
                )
            check_cancel()
            audit("verified", expected=baseline, actual=verified)
            evidence_repository = EvidenceRepository(database)
            def record_intake(evidence: Evidence) -> None:
                events = WorkflowRepository(database)
                events.record(evidence.id, None, "evidence", "operation", "completed", 100)
                events.record(evidence.id, None, "evidence", "after", "completed", 100,
                              baseline, verified, "Intake baseline verified in a second SHA-256 pass")
                events.record(evidence.id, None, "verify", "operation", "completed", 100)

            for registered in evidence_repository.list_by_case(case.id):
                if registered.file_path.resolve() == source:
                    if registered.sha256 != baseline:
                        evidence_repository.update_integrity_status(
                            registered.id, IntegrityStatus.MODIFIED
                        )
                        audit(
                            "integrity_failed",
                            evidence_id=str(registered.id),
                            expected=registered.sha256,
                            actual=baseline,
                        )
                        raise ValueError(
                            "This image differs from its registered hash. Original baseline preserved."
                        )
                    evidence = evidence_repository.update_integrity_status(
                        registered.id, IntegrityStatus.VERIFIED
                    )
                    audit("existing_evidence_verified", evidence_id=str(evidence.id))
                    record_intake(evidence)
                    report("Existing evidence verified", 100)
                    return IntakeResult(evidence, db_path, audit_path)
            evidence = evidence_repository.create(
                EvidenceCreate(
                    case_id=case.id,
                    original_filename=source.name,
                    file_path=source,
                    file_size_bytes=after.st_size,
                    sha256=baseline,
                    evidence_os=os_type,
                )
            )
            audit("registered", evidence_id=str(evidence.id))
            record_intake(evidence)
            report("Evidence verified and registered", 100)
            return IntakeResult(evidence, db_path, audit_path)
        except Exception as exc:
            audit("cancelled" if isinstance(exc, IntakeCancelled) else "failed", error=str(exc))
            raise
