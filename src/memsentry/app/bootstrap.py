"""Startup configuration shared by the desktop entry point."""

import os
import sys
from pathlib import Path

from memsentry.acquisition.config import load_environment_file


def load_portable_configuration() -> None:
    """Use the packaged executable directory or an explicitly supplied env file."""
    configured = os.environ.get("MEMSENTRY_ENV_FILE")
    if configured:
        load_environment_file(configured)
    elif getattr(sys, "frozen", False):
        executable_dir = Path(sys.executable).resolve().parent
        local_config = executable_dir / ".env"
        if local_config.is_file():
            load_environment_file(local_config)
        else:
            load_environment_file(executable_dir.parent / "MemSentryCases" / "env")


def configure_portable_settings() -> None:
    """Keep portable preferences with the workspace instead of on the host."""
    if os.environ.get("MEMSENTRY_PORTABLE") != "1":
        return
    from PySide6.QtCore import QSettings

    workspace = os.environ.get("MEMSENTRY_WORKSPACE")
    if not workspace:
        raise ValueError("Portable mode requires MEMSENTRY_WORKSPACE.")
    settings_dir = Path(workspace) / "settings"
    settings_dir.mkdir(parents=True, exist_ok=True)
    QSettings.setDefaultFormat(QSettings.Format.IniFormat)
    QSettings.setPath(
        QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(settings_dir)
    )
