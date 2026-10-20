import ctypes
import io
import subprocess
from types import SimpleNamespace

import pytest

from memsentry.acquisition.adapters.base import AcquisitionError
from memsentry.acquisition.adapters.windowsDumpManager import WindowsWinPmemAdapter
from memsentry.acquisition.windows_elevation import (
    ElevatedWindowsProcess,
    ShellExecuteInfo,
    WindowsAPI,
)


def native_api(launch):
    api = object.__new__(WindowsAPI)
    api.shell = SimpleNamespace(ShellExecuteExW=launch)
    api.ole = SimpleNamespace(CoInitializeEx=lambda *_: 0, CoUninitialize=lambda: None)
    return api


@pytest.mark.parametrize(
    "filename, override, modern",
    [
        ("winPmem.exe", None, True),
        ("winpmem_mini_x64.exe", None, False),
        ("WINPMEM_MINI_x86.exe", None, False),
        ("winpmem.exe", False, False),
        ("renamed_mini.exe", True, True),
    ],
)
def test_windows_command_versions(tmp_path, filename, override, modern):
    executable = tmp_path / "工具 with spaces" / filename
    output = tmp_path / "case with spaces" / "memory.raw"
    adapter = WindowsWinPmemAdapter(executable, acquire_subcommand=override)
    expected = (str(executable), "acquire", str(output)) if modern else (
        str(executable), str(output)
    )
    assert adapter.build_command(output) == expected


@pytest.mark.parametrize("modern", [True, False])
def test_native_launch_requests_uac_and_quotes_unicode_paths(tmp_path, modern):
    executable = tmp_path / "工具 with spaces" / "winpmem.exe"
    output = tmp_path / "case with spaces" / "memory.raw"
    observed = {}

    def launch(pointer):
        info = pointer._obj
        observed.update(
            verb=info.lpVerb,
            file=info.lpFile,
            parameters=info.lpParameters,
            mask=info.fMask,
            size=info.cbSize,
        )
        info.hProcess = 123
        return True

    api = native_api(launch)
    arguments = ["acquire", str(output)] if modern else [str(output)]
    assert api.launch((str(executable), *arguments)) == 123
    assert observed["verb"] == "runas"
    assert observed["file"] == str(executable)
    assert observed["parameters"] == subprocess.list2cmdline(arguments)
    assert observed["mask"] & 0x40
    assert observed["size"] == ctypes.sizeof(ShellExecuteInfo)


@pytest.mark.parametrize(
    "code, message", [(1223, "cancelled"), (5, "denied elevation"), (2, "error 2")]
)
def test_native_launch_errors_are_actionable(code, message, monkeypatch):
    monkeypatch.setattr(ctypes, "get_last_error", lambda: code, raising=False)
    monkeypatch.setattr(ctypes, "FormatError", lambda _: "mock Windows error", raising=False)
    calls = []
    api = native_api(lambda _: False)
    api.ole.CoUninitialize = lambda: calls.append("uninitialize")
    with pytest.raises(AcquisitionError, match=message):
        api.launch(("winpmem.exe", "memory.raw"))
    assert calls == ["uninitialize"]


def test_no_process_handle_is_reported():
    api = native_api(lambda _: True)
    with pytest.raises(AcquisitionError, match="process handle"):
        api.launch(("winpmem.exe", "memory.raw"))


def test_process_polls_real_exit_status_and_closes_handle_once(monkeypatch):
    codes = iter([None, 259])  # 259 is a valid exit code once the handle is signalled.
    closed = []
    api = SimpleNamespace(
        launch=lambda _: 123, exit_code=lambda *_: next(codes), close=closed.append
    )
    monkeypatch.setattr("memsentry.acquisition.windows_elevation.WindowsAPI", lambda: api)
    log = io.BytesIO()
    process = ElevatedWindowsProcess(("winpmem.exe", "memory.raw"), log)
    assert process.poll() is None
    assert process.wait() == 259
    assert process.poll() == 259
    process.close()
    assert closed == [123]
    assert b"exited with code 259" in log.getvalue()


def test_native_wait_handles_running_and_exit_code():
    api = native_api(lambda _: True)

    def set_code(handle, pointer):
        pointer._obj.value = 7
        return True

    api.kernel = SimpleNamespace(WaitForSingleObject=lambda *_: 0x102, GetExitCodeProcess=set_code)
    assert api.exit_code(123, 0) is None
    api.kernel.WaitForSingleObject = lambda *_: 0
    assert api.exit_code(123, 0) == 7


@pytest.mark.parametrize("modern", [True, False])
def test_windows_adapter_uses_uac_without_elevating_gui(tmp_path, monkeypatch, modern):
    executable = tmp_path / "winpmem.exe"
    executable.write_bytes(b"mock executable")
    executable.chmod(0o700)
    adapter = WindowsWinPmemAdapter(executable, acquire_subcommand=modern)
    monkeypatch.setattr(
        "memsentry.acquisition.adapters.windowsDumpManager.require_platform", lambda *_: None
    )
    monkeypatch.setattr(
        "memsentry.acquisition.adapters.windowsDumpManager.is_administrator", lambda: False
    )
    adapter.check_requirements()
    output = tmp_path / "memory.raw"

    class Process:
        returncode = 0
        closed = False

        def poll(self):
            return 0

        def close(self):
            self.closed = True

    process = Process()

    def launch(command, log):
        assert command == (
            (str(executable), "acquire", str(output))
            if modern else (str(executable), str(output))
        )
        assert not output.exists()
        output.write_bytes(b"fake capture")
        return process

    monkeypatch.setattr(
        "memsentry.acquisition.adapters.windowsDumpManager.ElevatedWindowsProcess", launch
    )
    result = adapter.capture(output)
    assert result.bytes_written == len(b"fake capture")
    assert process.closed


def test_already_admin_uses_direct_subprocess(tmp_path, monkeypatch):
    adapter = WindowsWinPmemAdapter(tmp_path / "winpmem.exe")
    monkeypatch.setattr(
        "memsentry.acquisition.adapters.windowsDumpManager.is_administrator", lambda: True
    )
    sentinel = object()
    monkeypatch.setattr(
        "memsentry.acquisition.adapters.base.subprocess.Popen", lambda *a, **k: sentinel
    )
    assert not adapter.elevation_required
    assert (
        adapter.start_process(adapter.build_command(tmp_path / "image.raw"), io.BytesIO())
        is sentinel
    )
