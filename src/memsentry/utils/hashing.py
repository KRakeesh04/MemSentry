"""SHA-256 cryptographic hashing utilities for forensic evidence files."""

from __future__ import annotations

import hashlib
from pathlib import Path


def compute_file_sha256(file_path: Path, chunk_size: int = 65536) -> str:
    """
    Compute the SHA-256 hexadecimal digest of a file in binary chunks.

    Args:
        file_path: Path to the target file.
        chunk_size: Size in bytes for each read chunk (default 64 KB).

    Returns:
        A 64-character hexadecimal SHA-256 string.

    Raises:
        FileNotFoundError: If the specified file path does not exist or is not a file.
        PermissionError: If the user lacks permissions to read the file.
        OSError: If an I/O error occurs while reading the file.
    """
    path = Path(file_path)
    if not path.exists() or not path.is_file():
        raise FileNotFoundError(f"Evidence file not found: {path}")

    hasher = hashlib.sha256()
    try:
        with path.open("rb") as file:
            while chunk := file.read(chunk_size):
                hasher.update(chunk)
    except PermissionError as exc:
        raise PermissionError(f"Permission denied reading evidence file: {path}") from exc
    except OSError as exc:
        raise OSError(f"Failed to read evidence file: {path}") from exc

    return hasher.hexdigest()
