"""Linux live memory capture through the approved AVML tool."""

from __future__ import annotations

import os
from pathlib import Path
from shutil import which

from memsentry.acquisition.adapters.base import (
    AcquisitionError,
    DumpAdapter,
    configured_executable,
    require_executable,
    require_platform,
)


class LinuxAvmlAdapter(DumpAdapter):
    """Capture Linux RAM with AVML using its fixed output-file interface."""

    tool_name = "AVML"
    target_os = "linux"

    def __init__(
        self, executable: str | Path | None = None, *, acquire_subcommand: bool = True
    ) -> None:
        self.acquire_subcommand = acquire_subcommand
        self._executable = configured_executable(executable, "MEMSENTRY_AVML", ("avml",))

    @property
    def executable(self) -> Path:
        return self._executable

    def build_command(self, output_path: Path) -> tuple[str, ...]:
        prefix = (
            (str(self.executable), "acquire")
            if self.acquire_subcommand
            else (str(self.executable),)
        )
        return (*prefix, str(output_path))

    def check_requirements(self) -> None:
        require_platform(self.target_os, self.tool_name)
        require_executable(self.executable, self.tool_name)
        if self.elevation_required:
            self._pkexec()

    @property
    def elevation_required(self) -> bool:
        return hasattr(os, "geteuid") and os.geteuid() != 0

    @staticmethod
    def _pkexec() -> str:
        executable = which("pkexec")
        if not executable:
            raise AcquisitionError(
                "Live capture needs Polkit's pkexec and a desktop authentication agent. "
                "Ask your system administrator to install/enable them, then retry. "
                "Importing an existing image does not require administrator access."
            )
        return str(Path(executable).resolve())

    def execution_command(self, output_path: Path) -> tuple[str, ...]:
        command = self.build_command(output_path)
        command = (str(self.executable.resolve()), *command[1:])
        if self.elevation_required:
            return (self._pkexec(), "--disable-internal-agent", *command)
        return command

    def failure_hint(self, log_path: Path) -> str:
        try:
            with log_path.open("rb") as stream:
                stream.seek(max(0, log_path.stat().st_size - 4096))
                details = stream.read(4096).decode("utf-8", errors="replace").lower()
        except OSError:
            return ""
        if "unrecognized subcommand" in details and "avml <command>" in details:
            return "Select 'AVML current: avml acquire output.lime' under AVML version and retry. "
        return ""
