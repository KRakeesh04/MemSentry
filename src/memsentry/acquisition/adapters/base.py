"""Shared safety and execution code for approved acquisition tools."""

from __future__ import annotations

import hashlib
import os
import subprocess
import time
from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from shutil import which
from typing import BinaryIO, Protocol, cast

ProgressCallback = Callable[[int, float | None], None]


class CaptureProcess(Protocol):
    @property
    def returncode(self) -> int | None: ...

    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...


class AcquisitionError(RuntimeError):
    """Raised when a live memory capture cannot be completed safely."""


@dataclass(frozen=True, slots=True)
class AcquisitionResult:
    """Metadata for a completed raw memory capture."""

    output_path: Path
    bytes_written: int
    sha256: str
    tool_name: str
    command: tuple[str, ...]
    started_at: datetime
    completed_at: datetime


class DumpAdapter(ABC):
    """Interface implemented by one approved acquisition tool per platform."""

    tool_name: str
    target_os: str

    @property
    @abstractmethod
    def executable(self) -> Path:
        """Return the configured acquisition executable."""

    @abstractmethod
    def build_command(self, output_path: Path) -> tuple[str, ...]:
        """Build the fixed, non-shell command for this adapter."""

    @abstractmethod
    def check_requirements(self) -> None:
        """Validate platform, privilege, and executable requirements."""

    @property
    def elevation_required(self) -> bool:
        """Whether the capture tool runs with privileges the GUI does not have."""
        return False

    def execution_command(self, output_path: Path) -> tuple[str, ...]:
        """Return the capture command, optionally through a system privilege broker."""
        return self.build_command(output_path)

    def failure_hint(self, log_path: Path) -> str:
        """Optional adapter-specific guidance for a failed capture."""
        return ""

    def start_process(self, command: tuple[str, ...], log: BinaryIO) -> CaptureProcess:
        return subprocess.Popen(
            command,
            stdout=log,
            stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL,
            shell=False,
        )

    def capture(
        self,
        output_path: Path,
        progress_callback: ProgressCallback | None = None,
    ) -> AcquisitionResult:
        """Run the tool and hash the finished output without touching source evidence."""

        self.check_requirements()
        output_path = output_path.expanduser().absolute()
        if output_path.is_symlink():
            raise AcquisitionError(f"Refusing a symlink capture destination: {output_path}")
        output_path = output_path.resolve()
        if output_path.exists():
            raise AcquisitionError(f"Refusing to overwrite existing output: {output_path}")
        output_path.parent.mkdir(parents=True, exist_ok=True)
        command = self.execution_command(output_path)
        elevated = self.elevation_required
        started_at = datetime.now(UTC)
        started_clock = time.monotonic()

        log_path = output_path.with_suffix(output_path.suffix + ".log")
        log = log_path.open("xb")
        try:
            if elevated and self.target_os == "linux":
                # AVML truncates the destination. Reserve it as this user so a
                # root-owned, restrictive file does not prevent later hashing.
                descriptor = os.open(output_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
                os.close(descriptor)
            process = self.start_process(command, log)
        except Exception as exc:
            log.close()
            if isinstance(exc, OSError):
                raise AcquisitionError(f"Could not start {self.tool_name}: {exc}") from exc
            raise

        try:
            while process.poll() is None:
                bytes_written = output_path.stat().st_size if output_path.exists() else 0
                elapsed = time.monotonic() - started_clock
                if progress_callback is not None:
                    progress_callback(bytes_written, elapsed)
                time.sleep(0.25)

            if process.returncode != 0:
                if elevated and self.target_os == "linux" and process.returncode in (126, 127):
                    reason = (
                        "Administrator authentication was cancelled. No evidence was registered."
                        if process.returncode == 126
                        else "Administrator authentication failed or no desktop authentication agent is available. "
                        "Ensure Polkit and a desktop authentication agent are installed and running."
                    )
                    raise AcquisitionError(f"{reason} Details: {log_path}")
                log.flush()
                raise AcquisitionError(
                    f"{self.tool_name} failed with exit code {process.returncode}. "
                    f"{self.failure_hint(log_path)}"
                    f"See {log_path}. Any partial capture is retained at {output_path}."
                )
        except BaseException:
            if process.poll() is None:
                if elevated:
                    # Do not abandon a root process or assume we may signal it.
                    process.wait()
                else:
                    # Non-elevated adapters launch a subprocess; elevated handles
                    # only support waiting and must never reach this branch.
                    local_process = cast("subprocess.Popen[bytes]", process)
                    local_process.terminate()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        local_process.kill()
                        process.wait()
            raise
        finally:
            if hasattr(process, "close"):
                process.close()
            log.close()

        if not output_path.is_file() or output_path.stat().st_size == 0:
            raise AcquisitionError(f"{self.tool_name} produced no usable memory image")
        if not os.access(output_path, os.R_OK):
            raise AcquisitionError(
                f"Capture completed but the image is not readable by this user: {output_path}. "
                "Ask an administrator to restore read access; no evidence was registered."
            )

        bytes_written = output_path.stat().st_size
        if progress_callback is not None:
            progress_callback(bytes_written, time.monotonic() - started_clock)
        completed_at = datetime.now(UTC)
        return AcquisitionResult(
            output_path=output_path,
            bytes_written=bytes_written,
            sha256=_sha256(output_path, progress_callback),
            tool_name=self.tool_name,
            command=command,
            started_at=started_at,
            completed_at=completed_at,
        )


def configured_executable(
    configured_path: str | Path | None,
    environment_variable: str,
    executable_names: Sequence[str],
) -> Path:
    """Resolve an explicit path, environment path, or executable on PATH."""

    candidate = configured_path or os.environ.get(environment_variable)
    if candidate:
        return Path(candidate).expanduser().resolve()
    for name in executable_names:
        found = which(name)
        if found:
            return Path(found).resolve()
    return Path(executable_names[0])


def require_executable(path: Path, tool_name: str) -> None:
    """Ensure a configured executable exists and is executable."""

    if not path.is_file():
        raise AcquisitionError(
            f"{tool_name} was not found at {path}. Configure its path or install it on PATH."
        )
    if os.name != "nt" and not os.access(path, os.X_OK):
        raise AcquisitionError(f"{tool_name} is not executable: {path}")


def require_elevated_privileges(tool_name: str) -> None:
    """Require administrator/root privileges before touching physical memory."""

    if os.name == "nt":
        import ctypes

        is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
    else:
        is_admin = os.geteuid() == 0
    if not is_admin:
        raise AcquisitionError(f"{tool_name} requires administrator/root privileges")


def require_platform(expected: str, tool_name: str) -> None:
    """Prevent a platform-specific tool from running on the wrong host."""

    actual = (
        "windows" if os.name == "nt" else ("macos" if os.uname().sysname == "Darwin" else "linux")
    )
    if actual != expected:
        raise AcquisitionError(f"{tool_name} is only supported on {expected} hosts")


def _sha256(path: Path, progress_callback: ProgressCallback | None = None) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as evidence_file:
        for chunk in iter(lambda: evidence_file.read(1024 * 1024), b""):
            digest.update(chunk)
            if progress_callback is not None:
                progress_callback(evidence_file.tell(), None)
    return digest.hexdigest()
