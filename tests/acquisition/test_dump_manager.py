from __future__ import annotations

import hashlib
from datetime import UTC, datetime
from pathlib import Path

from memsentry.acquisition.adapters.base import AcquisitionResult, DumpAdapter
from memsentry.acquisition.dump_manager import DumpManager


class FakeAdapter(DumpAdapter):
    tool_name = "test-tool"
    target_os = "linux"

    @property
    def executable(self) -> Path:
        return Path("test-tool")

    def build_command(self, output_path: Path) -> tuple[str, ...]:
        return ("test-tool", str(output_path))

    def check_requirements(self) -> None:
        return None

    def capture(self, output_path: Path, progress_callback=None) -> AcquisitionResult:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_bytes(b"test memory image")
        digest = hashlib.sha256(output_path.read_bytes()).hexdigest()
        now = datetime.now(UTC)
        return AcquisitionResult(
            output_path=output_path,
            bytes_written=output_path.stat().st_size,
            sha256=digest,
            tool_name=self.tool_name,
            command=self.build_command(output_path),
            started_at=now,
            completed_at=now,
        )


def test_capture_live_uses_case_evidence_directory(tmp_path: Path) -> None:
    result = DumpManager(FakeAdapter()).capture_live(tmp_path, "capture.raw")

    assert result.output_path == (tmp_path / "evidence/acquired/capture.raw").resolve()
    assert result.sha256 == hashlib.sha256(b"test memory image").hexdigest()
