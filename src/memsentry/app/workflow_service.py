"""Read-only SHA-256 gates around major evidence operations."""

import hashlib
from collections.abc import Callable
from typing import TypeVar
from uuid import UUID

from memsentry.models.evidence import Evidence, IntegrityStatus
from memsentry.storage.database import Database
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.workflow_repository import WorkflowRepository

STAGES = ("case", "evidence", "verify", "analyze", "investigate", "correlate", "findings", "report")


class IntegrityCheckError(RuntimeError):
    pass


T = TypeVar("T")


class WorkflowService:
    """Every supported operation must pass a fresh before/after check to advance."""

    def __init__(self, database: Database) -> None:
        self.database = database
        self.events = WorkflowRepository(database)
        self.evidence = EvidenceRepository(database)

    def verify(self, evidence: Evidence, run_id: UUID | str | None, stage: str, phase: str) -> None:
        self.events.record(evidence.id, run_id, stage, phase, "running", expected=evidence.sha256)
        digest = hashlib.sha256()
        actual = None
        try:
            before = evidence.file_path.stat()
            read = 0
            reported = 0
            with evidence.file_path.open("rb") as stream:
                while chunk := stream.read(4 * 1024 * 1024):
                    digest.update(chunk)
                    read += len(chunk)
                    percent = min(99, int(read * 100 / max(before.st_size, 1)))
                    if percent >= reported + 5:
                        reported = percent
                        self.events.record(
                            evidence.id, run_id, stage, phase, "running", percent, evidence.sha256
                        )
            after = evidence.file_path.stat()
            actual = digest.hexdigest()
            stable = (before.st_size, before.st_mtime_ns, before.st_ino) == (
                after.st_size,
                after.st_mtime_ns,
                after.st_ino,
            )
            if actual != evidence.sha256 or not stable:
                self.evidence.update_integrity_status(evidence.id, IntegrityStatus.MODIFIED)
                raise IntegrityCheckError(
                    "SHA-256 mismatch or image changed while hashing. Workflow stopped."
                )
        except Exception as exc:
            if isinstance(exc, OSError):
                self.evidence.update_integrity_status(evidence.id, IntegrityStatus.UNAVAILABLE)
            self.events.record(
                evidence.id,
                run_id,
                stage,
                phase,
                "failed",
                expected=evidence.sha256,
                actual=actual,
                message=str(exc),
            )
            raise IntegrityCheckError(str(exc)) from exc
        self.evidence.update_integrity_status(evidence.id, IntegrityStatus.VERIFIED)
        self.events.record(
            evidence.id,
            run_id,
            stage,
            phase,
            "completed",
            100,
            evidence.sha256,
            actual,
            "SHA-256 matches the registered baseline",
        )

    def execute(self, run_id: UUID, stage: str, operation: Callable[[], T]) -> T:
        """Run an operation only on registered evidence, retaining failed checkpoints."""
        if stage not in STAGES[3:]:
            raise ValueError("Unsupported workflow operation")
        run = AnalysisRunRepository(self.database).get_by_id(run_id)
        if run is None:
            raise ValueError("Analysis run is not registered")
        evidence = self.evidence.get_by_id(run.evidence_id)
        if evidence is None:
            raise ValueError("Evidence is not registered")
        self.database.initialize()
        if evidence.integrity_status != IntegrityStatus.VERIFIED:
            raise IntegrityCheckError("Evidence integrity is not verified. Workflow blocked.")
        if any(
            event["analysis_run_id"] == str(run_id)
            and event["phase"] != "operation"
            and event["status"] == "failed"
            for event in self.events.list_events(evidence.id, run_id)
        ):
            raise IntegrityCheckError(
                "This run has a failed SHA-256 checkpoint. Start a new run after verification."
            )
        self.verify(evidence, run_id, stage, "before")
        self.events.record(evidence.id, run_id, stage, "operation", "running")
        try:
            result = operation()
        except Exception as exc:
            self.events.record(evidence.id, run_id, stage, "operation", "failed", message=str(exc))
            self.verify(evidence, run_id, stage, "after")
            raise
        self.verify(evidence, run_id, stage, "after")
        self.events.record(evidence.id, run_id, stage, "operation", "completed", 100)
        return result
