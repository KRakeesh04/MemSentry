"""Locate read-only application resources in source and frozen distributions."""

import sys
from pathlib import Path


def resource_directory() -> Path:
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent / "_internal")) / "resources"
    return Path(__file__).resolve().parents[2] / "resources"
