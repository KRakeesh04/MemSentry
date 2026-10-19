"""Small, dependency-free configuration loader for portable acquisition."""

from __future__ import annotations

import os
from pathlib import Path

_PATH_VARIABLES = {"MEMSENTRY_AVML", "MEMSENTRY_WINPMEM", "MEMSENTRY_OSXPMEM"}


def load_environment_file(path: str | Path, *, override: bool = False) -> None:
    """Load approved variables from a dotenv-style file.

    Existing environment variables are preserved unless override is requested. Relative acquisition
    tool paths are resolved relative to the directory containing the file.
    """

    environment_file = Path(path).expanduser().resolve()
    if not environment_file.is_file():
        return

    values = {}
    for line_number, raw_line in enumerate(
        environment_file.read_text(encoding="utf-8").splitlines(), start=1
    ):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            raise ValueError(f"Invalid configuration at {environment_file}:{line_number}")

        key, value = (part.strip() for part in line.split("=", 1))
        if not key.startswith("MEMSENTRY_"):
            continue
        value = value.strip().strip("'\"")
        if key in _PATH_VARIABLES and value and not Path(value).is_absolute():
            value = str((environment_file.parent / value).resolve())
        values[key] = value
    for key, value in values.items():
        if override:
            os.environ[key] = value
        else:
            os.environ.setdefault(key, value)
