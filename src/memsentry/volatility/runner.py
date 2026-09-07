"""Volatility 3 subprocess execution runner for individual forensic plugins."""

from __future__ import annotations

import subprocess
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from memsentry.models.evidence import EvidenceOS
from memsentry.volatility.plugin_applicability import PluginApplicabilityService


class VolatilityRunnerError(RuntimeError):
    """Base exception for Volatility execution errors."""


class EvidenceFileNotFoundError(VolatilityRunnerError, FileNotFoundError):
    """Raised when evidence file does not exist or is not a file."""


class InvalidPluginError(VolatilityRunnerError, ValueError):
    """Raised when plugin name is not an approved core Volatility plugin."""


class VolatilityExecutionError(VolatilityRunnerError):
    """Raised when Volatility process execution fails or returns non-zero code."""


class VolatilityTimeoutError(VolatilityRunnerError, TimeoutError):
    """Raised when Volatility process execution times out."""


@dataclass(frozen=True)
class VolatilityResult:
    """Result of a single Volatility plugin execution."""

    success: bool
    plugin_name: str
    return_code: int
    output_path: Path | None
    stdout: str
    stderr: str
    error_message: str | None = None


class VolatilityRunner:
    """
    Executes a single core Volatility 3 plugin against a memory image file.

    Maintains strict input validation, subprocess isolation, and error handling.
    Does not access SQLite or depend on PySide6.
    """

    def __init__(
        self,
        python_executable: str | Path | None = None,
        plugin_applicability_service: type[
            PluginApplicabilityService
        ] = PluginApplicabilityService,
    ) -> None:
        self.python_executable = (
            str(python_executable) if python_executable else sys.executable
        )
        self.plugin_applicability_service = plugin_applicability_service

    def build_command(
        self,
        evidence_path: Path,
        plugin_name: str,
        output_dir: Path,
        extra_args: Sequence[str] | None = None,
    ) -> list[str]:
        """Construct subprocess command list for executing a plugin."""
        cmd = [
            self.python_executable,
            "-c",
            "import sys, volatility3.cli; sys.argv[0] = 'vol'; volatility3.cli.main()",
            "-f",
            str(evidence_path),
            "-o",
            str(output_dir),
            "-r",
            "json",
            plugin_name,
        ]
        if extra_args:
            cmd.extend(extra_args)
        return cmd

    def run_plugin(
        self,
        evidence_path: Path,
        plugin_name: str,
        output_dir: Path,
        evidence_os: EvidenceOS | None = None,
        timeout_seconds: float | None = 300.0,
        extra_args: Sequence[str] | None = None,
    ) -> VolatilityResult:
        """
        Execute a single approved Volatility 3 plugin against an evidence file.

        Args:
            evidence_path: Path to the evidence RAM image file.
            plugin_name: Approved core plugin name (e.g. 'windows.pslist').
            output_dir: Target directory to store output files.
            evidence_os: Optional target OS to validate plugin applicability.
            timeout_seconds: Subprocess timeout in seconds.
            extra_args: Optional additional arguments for Volatility CLI.

        Returns:
            VolatilityResult dataclass containing execution details and output file path.
        """
        path = Path(evidence_path)
        if not path.exists() or not path.is_file():
            raise EvidenceFileNotFoundError(f"Evidence image not found: {path}")

        if not self.plugin_applicability_service.is_core_plugin(plugin_name):
            raise InvalidPluginError(
                f"Plugin '{plugin_name}' is not an approved core Volatility plugin."
            )

        if (
            evidence_os is not None
            and not self.plugin_applicability_service.is_plugin_applicable(
                plugin_name, evidence_os
            )
        ):
            raise InvalidPluginError(
                f"Plugin '{plugin_name}' is not applicable for {evidence_os.value} evidence."
            )

        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        cmd = self.build_command(path, plugin_name, out_dir, extra_args)

        try:
            completed_proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            stderr = (
                exc.stderr
                if isinstance(exc.stderr, str)
                else (exc.stderr.decode() if exc.stderr else "")
            )
            stdout = (
                exc.output
                if isinstance(exc.output, str)
                else (exc.output.decode() if exc.output else "")
            )
            return VolatilityResult(
                success=False,
                plugin_name=plugin_name,
                return_code=-1,
                output_path=None,
                stdout=stdout,
                stderr=stderr,
                error_message=f"Volatility execution timed out after {timeout_seconds}s.",
            )
        except Exception as exc:
            return VolatilityResult(
                success=False,
                plugin_name=plugin_name,
                return_code=-1,
                output_path=None,
                stdout="",
                stderr=str(exc),
                error_message=f"Subprocess execution error: {exc}",
            )

        if completed_proc.returncode != 0:
            return VolatilityResult(
                success=False,
                plugin_name=plugin_name,
                return_code=completed_proc.returncode,
                output_path=None,
                stdout=completed_proc.stdout,
                stderr=completed_proc.stderr,
                error_message=(
                    f"Volatility returned non-zero exit code {completed_proc.returncode}: "
                    f"{completed_proc.stderr.strip()}"
                ),
            )

        output_file_name = f"{plugin_name.replace('.', '_')}.json"
        target_output_path = out_dir / output_file_name

        if completed_proc.stdout.strip():
            target_output_path.write_text(completed_proc.stdout, encoding="utf-8")

        output_exists = target_output_path.exists()
        return VolatilityResult(
            success=True,
            plugin_name=plugin_name,
            return_code=completed_proc.returncode,
            output_path=target_output_path if output_exists else None,
            stdout=completed_proc.stdout,
            stderr=completed_proc.stderr,
            error_message=None,
        )
