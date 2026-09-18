"""Optional macOS live memory capture through osxpmem."""

from __future__ import annotations

from pathlib import Path

from memsentry.acquisition.adapters.base import (
    DumpAdapter,
    configured_executable,
    require_elevated_privileges,
    require_executable,
    require_platform,
)


class MacOSPmemAdapter(DumpAdapter):
    """Capture macOS RAM with an externally installed osxpmem-compatible tool."""

    tool_name = "osxpmem"
    target_os = "macos"

    def __init__(self, executable: str | Path | None = None) -> None:
        self._executable = configured_executable(executable, "MEMSENTRY_OSXPMEM", ("osxpmem",))

    @property
    def executable(self) -> Path:
        return self._executable

    def build_command(self, output_path: Path) -> tuple[str, ...]:
        return (str(self.executable), str(output_path))

    def check_requirements(self) -> None:
        require_platform(self.target_os, self.tool_name)
        require_elevated_privileges(self.tool_name)
        require_executable(self.executable, self.tool_name)
