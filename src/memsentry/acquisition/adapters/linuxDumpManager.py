"""Linux live memory capture through the approved AVML tool."""

from __future__ import annotations

from pathlib import Path

from memsentry.acquisition.adapters.base import (
    DumpAdapter,
    configured_executable,
    require_elevated_privileges,
    require_executable,
    require_platform,
)


class LinuxAvmlAdapter(DumpAdapter):
    """Capture Linux RAM with AVML using its fixed output-file interface."""

    tool_name = "AVML"
    target_os = "linux"

    def __init__(
        self, executable: str | Path | None = None, *, acquire_subcommand: bool = False
    ) -> None:
        self.acquire_subcommand = acquire_subcommand
        self._executable = configured_executable(executable, "MEMSENTRY_AVML", ("avml",))

    @property
    def executable(self) -> Path:
        return self._executable

    def build_command(self, output_path: Path) -> tuple[str, ...]:
        prefix = (str(self.executable), "acquire") if self.acquire_subcommand else (str(self.executable),)
        return (*prefix, str(output_path))

    def check_requirements(self) -> None:
        require_platform(self.target_os, self.tool_name)
        require_elevated_privileges(self.tool_name)
        require_executable(self.executable, self.tool_name)
