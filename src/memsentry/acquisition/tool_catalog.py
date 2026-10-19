"""Discover configured tools without executing them or requesting privileges."""

import os
import platform
from dataclasses import dataclass
from pathlib import Path
from shutil import which


@dataclass(frozen=True)
class ToolOption:
    name: str
    host: str
    path: Path | None
    available: bool
    description: str


def available_tools() -> list[ToolOption]:
    host = platform.system()
    options = []
    for name, target, variable, binary in (
        ("AVML", "Linux", "MEMSENTRY_AVML", "avml"),
        ("WinPmem mini", "Windows", "MEMSENTRY_WINPMEM", "winpmem_mini_x64.exe"),
    ):
        configured = os.environ.get(variable)
        discovered = configured or which(binary)
        path = Path(discovered).expanduser().resolve() if discovered else None
        usable = (
            path is not None and path.is_file() and (os.name == "nt" or os.access(path, os.X_OK))
        )
        if host != target:
            configured_status = "Configured" if path is not None and path.is_file() else "Not found / not configured"
            reason = f"{configured_status} · {target} only · unavailable on this host"
        elif not usable:
            reason = f"Not available · configure {variable} or choose a compatible executable"
        else:
            reason = f"Ready · {'environment / .env' if configured else 'PATH'} · {path}"
        options.append(ToolOption(name, target, path, bool(usable and host == target), reason))
    return options
