"""Approved, platform-specific memory acquisition tool adapters."""

from memsentry.acquisition.adapters.base import AcquisitionError, AcquisitionResult, DumpAdapter
from memsentry.acquisition.adapters.linuxDumpManager import LinuxAvmlAdapter
from memsentry.acquisition.adapters.macDumpManager import MacOSPmemAdapter
from memsentry.acquisition.adapters.windowsDumpManager import WindowsWinPmemAdapter

__all__ = [
    "AcquisitionError",
    "AcquisitionResult",
    "DumpAdapter",
    "LinuxAvmlAdapter",
    "MacOSPmemAdapter",
    "WindowsWinPmemAdapter",
]
