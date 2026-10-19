"""Persist resolved acquisition paths without retaining unrelated environment values."""

import os
from pathlib import Path

from PySide6.QtCore import QSettings

from memsentry.acquisition.config import load_environment_file

_TOOL_VARIABLES = ("MEMSENTRY_AVML", "MEMSENTRY_WINPMEM", "MEMSENTRY_OSXPMEM")


def restore_tool_settings() -> None:
    settings = QSettings("MemSentry", "MemSentry")
    for key in _TOOL_VARIABLES:
        value = settings.value(f"acquisition/{key}")
        if value is not None:
            os.environ.setdefault(key, str(value))


def import_tool_settings(path: str) -> None:
    if not Path(path).is_file():
        raise FileNotFoundError(f"Configuration file not found: {path}")
    load_environment_file(path, override=True)
    settings = QSettings("MemSentry", "MemSentry")
    for key in _TOOL_VARIABLES:
        if key in os.environ:
            settings.setValue(f"acquisition/{key}", os.environ[key])
    settings.sync()
    if settings.status() != QSettings.Status.NoError:
        raise OSError("Could not save acquisition tool settings.")
