"""Windows live memory capture through the approved WinPmem tool."""

from __future__ import annotations

from pathlib import Path

from memsentry.acquisition.adapters.base import (
    DumpAdapter,
    configured_executable,
    require_elevated_privileges,
    require_executable,
    require_platform,
)


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
        return (str(self.executable), str(output_path))

    def check_requirements(self) -> None:
        require_platform(self.target_os, self.tool_name)
        require_elevated_privileges(self.tool_name)
        require_executable(self.executable, self.tool_name)
