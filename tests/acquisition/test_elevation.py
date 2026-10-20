import hashlib
import os
import stat
import subprocess

import pytest

from memsentry.acquisition.adapters.base import AcquisitionError
from memsentry.acquisition.adapters.linuxDumpManager import LinuxAvmlAdapter

pytestmark = pytest.mark.linux


@pytest.fixture
def adapter(tmp_path, monkeypatch):
    executable = tmp_path / "tools with spaces" / "avml"
    executable.parent.mkdir()
    executable.write_bytes(b"mock tool, never executed")
    executable.chmod(0o700)
    monkeypatch.setattr(LinuxAvmlAdapter, "elevation_required", property(lambda _: True))
    monkeypatch.setattr(
        "memsentry.acquisition.adapters.linuxDumpManager.require_platform", lambda *_: None
    )
    monkeypatch.setattr(
        "memsentry.acquisition.adapters.linuxDumpManager.which", lambda _: str(tmp_path / "pkexec")
    )
    return LinuxAvmlAdapter(executable)


def test_pkexec_receives_separate_arguments_and_disables_text_password_prompt(adapter, tmp_path):
    output = tmp_path / "capture with spaces.lime"
    command = adapter.execution_command(output)
    assert command == (
        str(tmp_path / "pkexec"),
        "--disable-internal-agent",
        str(adapter.executable),
        "acquire",
        str(output),
    )


def test_root_uses_tool_directly(adapter, tmp_path, monkeypatch):
    monkeypatch.setattr(LinuxAvmlAdapter, "elevation_required", property(lambda _: False))
    monkeypatch.setattr("memsentry.acquisition.adapters.linuxDumpManager.which", lambda _: None)
    adapter.check_requirements()
    assert adapter.execution_command(tmp_path / "memory.lime")[0] == str(adapter.executable)


def test_missing_pkexec_explains_desktop_setup(adapter, monkeypatch):
    monkeypatch.setattr("memsentry.acquisition.adapters.linuxDumpManager.which", lambda _: None)
    with pytest.raises(AcquisitionError, match="desktop authentication agent"):
        adapter.check_requirements()


def test_elevated_capture_reserves_user_owned_output_and_hashes(adapter, tmp_path, monkeypatch):
    output = tmp_path / "memory.lime"
    updates = []

    def start(command, **kwargs):
        assert command[1] == "--disable-internal-agent"
        assert kwargs["stdin"] == subprocess.DEVNULL
        assert kwargs["shell"] is False
        assert output.is_file()
        if os.name != "nt":
            assert stat.S_IMODE(output.stat().st_mode) == 0o600
            assert output.stat().st_uid == os.getuid()
        output.write_bytes(b"synthetic memory")
        return type("Process", (), {"poll": lambda self: 0, "returncode": 0})()

    monkeypatch.setattr("memsentry.acquisition.adapters.base.subprocess.Popen", start)
    result = adapter.capture(output, lambda *args: updates.append(args))
    assert result.sha256 == hashlib.sha256(b"synthetic memory").hexdigest()
    assert updates[-1][1] is None


@pytest.mark.parametrize("code,message", [(126, "cancelled"), (127, "authentication failed")])
def test_denied_authentication_produces_actionable_error(
    adapter, tmp_path, monkeypatch, code, message
):
    process = type("Process", (), {"poll": lambda self: code, "returncode": code})()
    monkeypatch.setattr(
        "memsentry.acquisition.adapters.base.subprocess.Popen", lambda *a, **k: process
    )
    with pytest.raises(AcquisitionError, match=message):
        adapter.capture(tmp_path / "memory.lime")


def test_existing_image_is_never_truncated(adapter, tmp_path, monkeypatch):
    output = tmp_path / "memory.lime"
    output.write_bytes(b"original evidence")

    def unexpected(*args, **kwargs):
        pytest.fail("Must not request elevation for an existing output")

    monkeypatch.setattr("memsentry.acquisition.adapters.base.subprocess.Popen", unexpected)
    with pytest.raises(AcquisitionError, match="overwrite"):
        adapter.capture(output)
    assert output.read_bytes() == b"original evidence"


def test_elevated_process_is_reaped_on_callback_failure(adapter, tmp_path, monkeypatch):
    class Process:
        returncode = None
        waited = False

        def poll(self):
            return self.returncode

        def wait(self):
            self.waited = True
            self.returncode = 0

    process = Process()
    monkeypatch.setattr(
        "memsentry.acquisition.adapters.base.subprocess.Popen", lambda *a, **k: process
    )

    def callback(*args):
        raise RuntimeError("progress failure")

    with pytest.raises(RuntimeError, match="progress failure"):
        adapter.capture(tmp_path / "memory.lime", callback)
    assert process.waited
