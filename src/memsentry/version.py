"""Application version information."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

_version_file = Path(__file__).parents[2] / "version.txt"
if _version_file.is_file():
    __version__ = _version_file.read_text(encoding="utf-8").strip()
else:
    try:
        __version__ = version("memsentry")
    except PackageNotFoundError:
        __version__ = "0.0.0"
