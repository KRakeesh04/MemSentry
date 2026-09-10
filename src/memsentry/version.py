"""Application version information."""

from importlib.metadata import PackageNotFoundError, version
from pathlib import Path

try:
    __version__ = version("memsentry")
except PackageNotFoundError:
    __version__ = (Path(__file__).parents[2] / "version.txt").read_text(encoding="utf-8").strip()
