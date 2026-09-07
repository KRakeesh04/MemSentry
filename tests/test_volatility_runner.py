"""Tests for the VolatilityRunner subprocess execution service."""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any

import pytest

from memsentry.models.evidence import EvidenceOS
from memsentry.volatility.runner import (
    EvidenceFileNotFoundError,
    InvalidPluginError,
    VolatilityResult,
    VolatilityRunner,
)


def test_command_construction(tmp_path: Path) -> None:
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"DATA")
    out_dir = tmp_path / "output"

    runner = VolatilityRunner(python_executable="python_mock")
    cmd = runner.build_command(evidence, "windows.pslist", out_dir, extra_args=["--arg1"])

    assert cmd[0] == "python_mock"
    assert cmd[1] == "-c"
    assert "volatility3.cli" in cmd[2]
    assert "-f" in cmd
    assert str(evidence) in cmd
    assert "-o" in cmd
    assert str(out_dir) in cmd
    assert "-r" in cmd
    assert "json" in cmd
    assert "windows.pslist" in cmd
    assert "--arg1" in cmd


def test_missing_evidence_file_raises_error(tmp_path: Path) -> None:
    runner = VolatilityRunner()
    missing_file = tmp_path / "does_not_exist.raw"
    out_dir = tmp_path / "output"

    with pytest.raises(EvidenceFileNotFoundError, match="Evidence image not found"):
        runner.run_plugin(missing_file, "windows.pslist", out_dir)


def test_invalid_plugin_raises_error(tmp_path: Path) -> None:
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"DATA")
    out_dir = tmp_path / "output"
    runner = VolatilityRunner()

    with pytest.raises(InvalidPluginError, match="not an approved core Volatility plugin"):
        runner.run_plugin(evidence, "windows.unauthorized_custom_plugin", out_dir)


def test_non_applicable_plugin_os_raises_error(tmp_path: Path) -> None:
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"DATA")
    out_dir = tmp_path / "output"
    runner = VolatilityRunner()

    with pytest.raises(InvalidPluginError, match="not applicable for linux evidence"):
        runner.run_plugin(evidence, "windows.pslist", out_dir, evidence_os=EvidenceOS.LINUX)


def test_successful_execution_and_output_file_creation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"DATA")
    out_dir = tmp_path / "output"

    mock_json = '{"processes": [{"pid": 4, "name": "System"}]}'

    def mock_subprocess_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        assert kwargs.get("shell") is not True
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=mock_json, stderr="")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    runner = VolatilityRunner()
    result = runner.run_plugin(evidence, "windows.pslist", out_dir, evidence_os=EvidenceOS.WINDOWS)

    assert isinstance(result, VolatilityResult)
    assert result.success is True
    assert result.return_code == 0
    assert result.output_path is not None
    assert result.output_path.name == "windows_pslist.json"
    assert result.output_path.read_text(encoding="utf-8") == mock_json
    assert result.stdout == mock_json
    assert result.stderr == ""
    assert result.error_message is None


def test_non_zero_exit_code_handling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"DATA")
    out_dir = tmp_path / "output"

    def mock_subprocess_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=cmd, returncode=1, stdout="", stderr="Symbol table missing"
        )

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    runner = VolatilityRunner()
    result = runner.run_plugin(evidence, "windows.pslist", out_dir)

    assert result.success is False
    assert result.return_code == 1
    assert result.output_path is None
    assert "Symbol table missing" in result.stderr
    assert "non-zero exit code 1" in (result.error_message or "")


def test_timeout_handling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"DATA")
    out_dir = tmp_path / "output"

    def mock_subprocess_run(cmd: list[str], **kwargs: Any) -> None:
        raise subprocess.TimeoutExpired(cmd=cmd, timeout=5.0, output="partial", stderr="timeout")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    runner = VolatilityRunner()
    result = runner.run_plugin(evidence, "windows.pslist", out_dir, timeout_seconds=5.0)

    assert result.success is False
    assert result.return_code == -1
    assert result.output_path is None
    assert "timed out after 5.0s" in (result.error_message or "")


def test_unexpected_exception_handling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    evidence = tmp_path / "memory.raw"
    evidence.write_bytes(b"DATA")
    out_dir = tmp_path / "output"

    def mock_subprocess_run(cmd: list[str], **kwargs: Any) -> None:
        raise OSError("Subprocess spawn error")

    monkeypatch.setattr(subprocess, "run", mock_subprocess_run)

    runner = VolatilityRunner()
    result = runner.run_plugin(evidence, "windows.pslist", out_dir)

    assert result.success is False
    assert result.return_code == -1
    assert result.output_path is None
    assert "Subprocess execution error" in (result.error_message or "")
