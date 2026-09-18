"""Coordinate live capture, hashing, and evidence registration."""

from __future__ import annotations

import sys
from datetime import UTC, datetime
from pathlib import Path
from uuid import UUID

from memsentry.acquisition.adapters.base import AcquisitionResult, DumpAdapter, ProgressCallback
from memsentry.acquisition.adapters.linuxDumpManager import LinuxAvmlAdapter
from memsentry.acquisition.adapters.macDumpManager import MacOSPmemAdapter
from memsentry.acquisition.adapters.windowsDumpManager import WindowsWinPmemAdapter
from memsentry.acquisition.config import load_environment_file
from memsentry.models.evidence import Evidence, EvidenceCreate, EvidenceOS
from memsentry.storage.repositories.evidence_repository import EvidenceRepository


class DumpManagerError(ValueError):
    """Raised when a capture request cannot be safely placed in the case."""


class DumpManager:
    """Select the host adapter and create immutable case evidence."""

    def __init__(
        self,
        adapter: DumpAdapter | None = None,
        environment_file: str | Path | None = None,
    ) -> None:
        if environment_file is not None:
            load_environment_file(environment_file)
        self.adapter = adapter or self._default_adapter()

    def capture_live(
        self,
        case_directory: str | Path,
        filename: str | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> AcquisitionResult:
        """Capture into ``case_directory/evidence/acquired`` and return its hash."""

        case_path = Path(case_directory).expanduser().resolve()
        output_name = filename or f"live-{datetime.now(UTC):%Y%m%dT%H%M%SZ}.raw"
        if not output_name or Path(output_name).name != output_name:
            raise DumpManagerError("Capture filename must be a single file name")
        output_path = case_path / "evidence" / "acquired" / output_name
        return self.adapter.capture(output_path, progress_callback)

    def capture_and_register(
        self,
        case_id: UUID,
        case_directory: str | Path,
        evidence_repository: EvidenceRepository,
        filename: str | None = None,
        progress_callback: ProgressCallback | None = None,
    ) -> tuple[AcquisitionResult, Evidence]:
        """Capture RAM and register the resulting read-only image in SQLite."""

        result = self.capture_live(case_directory, filename, progress_callback)
        evidence = evidence_repository.create(
            EvidenceCreate(
                case_id=case_id,
                original_filename=result.output_path.name,
                file_path=result.output_path,
                file_size_bytes=result.bytes_written,
                sha256=result.sha256,
                evidence_os=EvidenceOS(self.adapter.target_os),
            )
        )
        return result, evidence

    @staticmethod
    def _default_adapter() -> DumpAdapter:
        if sys.platform.startswith("win"):
            return WindowsWinPmemAdapter()
        if sys.platform == "darwin":
            return MacOSPmemAdapter()
        if sys.platform.startswith("linux"):
            return LinuxAvmlAdapter()
        raise RuntimeError(f"Unsupported acquisition host platform: {sys.platform}")
