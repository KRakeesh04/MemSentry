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

    def __init__(
        self, executable: str | Path | None = None, *, acquire_subcommand: bool | None = None
    ) -> None:
        self._executable = configured_executable(
            executable,
            "MEMSENTRY_WINPMEM",
            ("winpmem_mini_x64.exe", "winpmem.exe", "winpmem"),
        )
        # Mini builds use the positional output interface. Explicit selection
        # supports renamed binaries without probing or retrying a live capture.
        self.acquire_subcommand = (
            "mini" not in self.executable.name.lower()
            if acquire_subcommand is None
            else acquire_subcommand
        )

    @property
    def executable(self) -> Path:
        return self._executable

    def build_command(self, output_path: Path) -> tuple[str, ...]:
        prefix: tuple[str, ...] = (str(self.executable.resolve()),)
        if self.acquire_subcommand:
            prefix += ("acquire",)
        return (*prefix, str(output_path))

    def check_requirements(self) -> None:
        require_platform(self.target_os, self.tool_name)
        require_executable(self.executable, self.tool_name)
        if self.executable.suffix.lower() != ".exe":
            raise AcquisitionError("Select a standalone WinPmem .exe executable.")

    @property
    def elevation_required(self) -> bool:
        return not is_administrator()

    def start_process(self, command: tuple[str, ...], log: BinaryIO) -> CaptureProcess:
        if self.elevation_required:
            return ElevatedWindowsProcess(command, log)
        return super().start_process(command, log)
