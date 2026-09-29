"""Windows live memory capture through the approved WinPmem tool."""

from __future__ import annotations

from pathlib import Path
from typing import BinaryIO

from memsentry.acquisition.adapters.base import (
    AcquisitionError,
    CaptureProcess,
    DumpAdapter,
    configured_executable,
    require_executable,
    require_platform,
)
from memsentry.acquisition.windows_elevation import ElevatedWindowsProcess, is_administrator


class WindowsWinPmemAdapter(DumpAdapter):
    """Capture Windows RAM with WinPmem using its fixed output-file interface."""

    tool_name = "WinPmem"
    target_os = "windows"

    def __init__(self, executable: str | Path | None = None) -> None:
        self._executable = configured_executable(
            executable,
            "MEMSENTRY_WINPMEM",
            ("winpmem_mini_x64.exe", "winpmem.exe", "winpmem"),
        )

    @property
    def executable(self) -> Path:
        return self._executable

    def build_command(self, output_path: Path) -> tuple[str, ...]:
        return (str(self.executable.resolve()), str(output_path))

    def check_requirements(self) -> None:
        require_platform(self.target_os, self.tool_name)
        require_executable(self.executable, self.tool_name)
        if self.executable.suffix.lower() != ".exe":
            raise AcquisitionError("Select the standalone WinPmem mini .exe executable.")

    @property
    def elevation_required(self) -> bool:
        return not is_administrator()

    def start_process(self, command: tuple[str, ...], log: BinaryIO) -> CaptureProcess:
        if self.elevation_required:
            return ElevatedWindowsProcess(command, log)
        return super().start_process(command, log)
