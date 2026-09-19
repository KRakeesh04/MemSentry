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
        load_environment_file(Path(sys.executable).resolve().parent / ".env")
