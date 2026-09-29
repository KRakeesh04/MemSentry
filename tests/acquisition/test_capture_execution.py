import hashlib
import subprocess

import pytest

from memsentry.acquisition.adapters.base import AcquisitionError
from memsentry.acquisition.adapters.linuxDumpManager import LinuxAvmlAdapter


@pytest.fixture(autouse=True)
def direct_capture(monkeypatch):
    monkeypatch.setattr(LinuxAvmlAdapter, "elevation_required", property(lambda _: False))


def test_capture_logs_to_file_and_hashes_without_shell(tmp_path, monkeypatch):
    adapter = LinuxAvmlAdapter(tmp_path / "avml")
    monkeypatch.setattr(adapter, "check_requirements", lambda: None)
    output = tmp_path / "memory.lime"

    def start(command, **kwargs):
        assert kwargs["shell"] is False
        assert kwargs["stderr"] == subprocess.STDOUT
        kwargs["stdout"].write(b"tool diagnostics")
        output.write_bytes(b"synthetic capture")
        return type("Process", (), {"poll": lambda self: 0, "returncode": 0})()

    monkeypatch.setattr("memsentry.acquisition.adapters.base.subprocess.Popen", start)
    result = adapter.capture(output)
    assert result.sha256 == hashlib.sha256(b"synthetic capture").hexdigest()
    assert output.with_suffix(".lime.log").read_bytes() == b"tool diagnostics"
    with pytest.raises(AcquisitionError, match="overwrite"):
        adapter.capture(output)


def test_cancel_terminates_tool_and_retains_partial_capture(tmp_path, monkeypatch):
    adapter = LinuxAvmlAdapter(tmp_path / "avml")
    monkeypatch.setattr(adapter, "check_requirements", lambda: None)
    output = tmp_path / "partial.lime"

    class Process:
        terminated = False

        def poll(self):
            return None

        def terminate(self):
            self.terminated = True

        def wait(self, timeout=None):
            return 0

    process = Process()

    def start(*args, **kwargs):
        output.write_bytes(b"partial test capture")
        return process

    def cancel(*args):
        raise RuntimeError("cancelled")

    monkeypatch.setattr("memsentry.acquisition.adapters.base.subprocess.Popen", start)
    with pytest.raises(RuntimeError, match="cancelled"):
        adapter.capture(output, cancel)
    assert process.terminated
    assert output.read_bytes() == b"partial test capture"


def test_avml_command_profiles(tmp_path):
    executable = tmp_path / "avml"
    output = tmp_path / "capture.lime"
    assert LinuxAvmlAdapter(executable, acquire_subcommand=False).build_command(output) == (
        str(executable),
        str(output),
    )
    assert LinuxAvmlAdapter(executable).build_command(output) == (
        str(executable),
        "acquire",
        str(output),
    )


def test_legacy_cli_mismatch_reports_correct_profile(tmp_path, monkeypatch):
    adapter = LinuxAvmlAdapter(tmp_path / "avml", acquire_subcommand=False)
    monkeypatch.setattr(adapter, "check_requirements", lambda: None)

    def start(command, **kwargs):
        kwargs["stdout"].write(
            b"error: unrecognized subcommand '/case/memory.lime'\nUsage: avml <COMMAND>\n"
        )
        return type("Process", (), {"poll": lambda self: 2, "returncode": 2})()

    monkeypatch.setattr("memsentry.acquisition.adapters.base.subprocess.Popen", start)
    with pytest.raises(AcquisitionError, match=r"Select 'AVML current: avml acquire output\.lime'"):
        adapter.capture(tmp_path / "memory.lime")
