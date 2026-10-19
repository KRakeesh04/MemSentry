"""Bounded, cancellable copying of read-only evidence into a private intake directory."""

import os
import shutil
from collections.abc import Callable
from pathlib import Path

COPY_CHUNK_BYTES = 4 * 1024 * 1024
COPY_RESERVE_BYTES = 16 * 1024 * 1024


def check_copy_space(directory: Path, size: int) -> tuple[int, int]:
    """Leave room for database/audit writes in addition to the full logical image size."""
    free = shutil.disk_usage(directory).free
    required = size + COPY_RESERVE_BYTES
    if free < required:
        raise ValueError(
            f"Insufficient free space to copy evidence: {required:,} bytes required "
            f"(including {COPY_RESERVE_BYTES:,} bytes of reserve), {free:,} bytes available."
        )
    return free, required


def copy_image(
    source: Path,
    destination: Path,
    size: int,
    check_cancel: Callable[[], None],
    progress: Callable[[str, int], None],
) -> None:
    """Create a new file exclusively; the caller owns cleanup and hash verification."""
    check_copy_space(destination.parent, size)
    check_cancel()
    with source.open("rb") as original, destination.open("xb") as copied:
        written = 0
        progress("Copying evidence into case", 0)
        while written < size:
            check_cancel()
            chunk = original.read(min(COPY_CHUNK_BYTES, size - written))
            if not chunk:
                raise ValueError("Evidence changed during copying: source became shorter.")
            copied.write(chunk)
            written += len(chunk)
            progress("Copying evidence into case", min(99, written * 100 // max(size, 1)))
        if original.read(1):
            raise ValueError("Evidence changed during copying: source became larger.")
        copied.flush()
        os.fsync(copied.fileno())
    check_cancel()
