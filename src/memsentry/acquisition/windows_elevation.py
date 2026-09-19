"""Native UAC launch and process monitoring, without collecting credentials."""

from __future__ import annotations

import ctypes
import os
import subprocess
from pathlib import Path
from typing import BinaryIO

from memsentry.acquisition.adapters.base import AcquisitionError


class ShellExecuteInfo(ctypes.Structure):
    """SHELLEXECUTEINFOW with pointer-sized handles on 32/64-bit Windows."""

    _fields_ = [
        ("cbSize", ctypes.c_uint32),
        ("fMask", ctypes.c_uint32),
        ("hwnd", ctypes.c_void_p),
        ("lpVerb", ctypes.c_wchar_p),
        ("lpFile", ctypes.c_wchar_p),
        ("lpParameters", ctypes.c_wchar_p),
        ("lpDirectory", ctypes.c_wchar_p),
        ("nShow", ctypes.c_int),
        ("hInstApp", ctypes.c_void_p),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", ctypes.c_wchar_p),
        ("hkeyClass", ctypes.c_void_p),
        ("dwHotKey", ctypes.c_uint32),
        ("hIcon", ctypes.c_void_p),
        ("hProcess", ctypes.c_void_p),
    ]


class WindowsAPI:
    """Load Win32 APIs only when actually used on Windows."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise AcquisitionError("Windows UAC is only available on Windows.")
        self.shell = ctypes.WinDLL("shell32", use_last_error=True)
        self.kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        self.ole = ctypes.WinDLL("ole32", use_last_error=True)
        self.shell.ShellExecuteExW.argtypes = [ctypes.POINTER(ShellExecuteInfo)]
        self.shell.ShellExecuteExW.restype = ctypes.c_int
        self.shell.IsUserAnAdmin.argtypes = []
        self.shell.IsUserAnAdmin.restype = ctypes.c_int
        self.kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.kernel.WaitForSingleObject.restype = ctypes.c_uint32
        self.kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        self.kernel.GetExitCodeProcess.restype = ctypes.c_int
        self.kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        self.kernel.CloseHandle.restype = ctypes.c_int
        self.ole.CoInitializeEx.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        self.ole.CoInitializeEx.restype = ctypes.c_int32
        self.ole.CoUninitialize.argtypes = []
        self.ole.CoUninitialize.restype = None

    def launch(self, command: tuple[str, ...]) -> int:
        info = ShellExecuteInfo()
        info.cbSize = ctypes.sizeof(info)
        # Retain process handle, finish launch synchronously, suppress error UI
        # (the native UAC security prompt is explicitly exempt).
        info.fMask = 0x00000040 | 0x00000100 | 0x00000400
        info.lpVerb = "runas"
        info.lpFile = command[0]
        info.lpParameters = subprocess.list2cmdline(command[1:])
        info.lpDirectory = str(Path(command[0]).parent)
        info.nShow = 1  # WinPmem's own console shows diagnostic output.
        initialized = self.ole.CoInitializeEx(None, 2)
        if initialized < 0 and initialized != -2147417850:  # RPC_E_CHANGED_MODE
            raise AcquisitionError(
                f"Could not initialize Windows elevation (HRESULT {initialized})."
            )
        try:
            if not self.shell.ShellExecuteExW(ctypes.byref(info)):
                code = ctypes.get_last_error()
                if code == 1223:
                    raise AcquisitionError(
                        "Windows UAC request was cancelled. No evidence was registered."
                    )
                if code == 5:
                    raise AcquisitionError(
                        "Windows denied elevation. Ask an administrator to check UAC policy and tool access."
                    )
                raise AcquisitionError(
                    f"Could not elevate WinPmem: Windows error {code} ({ctypes.FormatError(code).strip()})."
                )
            if not info.hProcess:
                raise AcquisitionError(
                    "Windows did not return a capture process handle; capture cannot be monitored."
                )
            return info.hProcess
        finally:
            if initialized >= 0:
                self.ole.CoUninitialize()

    def exit_code(self, handle: int, milliseconds: int) -> int | None:
        state = self.kernel.WaitForSingleObject(handle, milliseconds)
        if state == 0x102:  # WAIT_TIMEOUT
            return None
        if state != 0:
            raise AcquisitionError(f"Could not monitor elevated WinPmem (wait result {state}).")
        code = ctypes.c_uint32()
        if not self.kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
            raise AcquisitionError("Could not read elevated WinPmem's exit status.")
        return code.value

    def close(self, handle: int) -> None:
        self.kernel.CloseHandle(handle)


def is_administrator() -> bool:
    return bool(WindowsAPI().shell.IsUserAnAdmin())


class ElevatedWindowsProcess:
    """Minimal subprocess-compatible lifetime around a UAC process handle."""

    def __init__(self, command: tuple[str, ...], log: BinaryIO) -> None:
        self.api = WindowsAPI()
        self.log = log
        self.returncode: int | None = None
        self.handle: int | None = None
        log.write(
            b"Windows UAC requested. WinPmem console output is not redirected; this log records launch/exit status.\n"
        )
        log.flush()
        self.handle = self.api.launch(command)
        try:
            log.write(b"UAC approved; elevated WinPmem started.\n")
            log.flush()
        except OSError:
            # A logging failure must not orphan an already elevated capture.
            try:
                self.api.exit_code(self.handle, 0xFFFFFFFF)
            finally:
                self.close()
            raise

    def poll(self) -> int | None:
        return self._wait(0)

    def wait(self, timeout: float | None = None) -> int:
        code = self._wait(0xFFFFFFFF if timeout is None else int(timeout * 1000))
        if code is None:
            raise subprocess.TimeoutExpired("WinPmem", timeout)
        return code

    def _wait(self, milliseconds: int) -> int | None:
        if self.returncode is not None:
            return self.returncode
        if self.handle is None:
            raise AcquisitionError("Elevated capture process handle is closed.")
        code = self.api.exit_code(self.handle, milliseconds)
        if code is not None:
            self.returncode = code
            self.close()
            self.log.write(f"WinPmem exited with code {code}.\n".encode())
            self.log.flush()
        return code

    def close(self) -> None:
        if self.handle is not None:
            self.api.close(self.handle)
            self.handle = None
