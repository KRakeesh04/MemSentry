"""Tests for the SHA-256 file hashing utility."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from memsentry.utils.hashing import compute_file_sha256


def test_known_file_sha256(tmp_path: Path) -> None:
    content = b"hello world\n"
    file_path = tmp_path / "sample.txt"
    file_path.write_bytes(content)

    expected_hash = hashlib.sha256(content).hexdigest()
    actual_hash = compute_file_sha256(file_path)

    assert actual_hash == expected_hash
    assert len(actual_hash) == 64


def test_empty_file_sha256(tmp_path: Path) -> None:
    file_path = tmp_path / "empty.bin"
    file_path.write_bytes(b"")

    expected_hash = hashlib.sha256(b"").hexdigest()
    actual_hash = compute_file_sha256(file_path)

    assert actual_hash == expected_hash
    assert actual_hash == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def test_chunked_reading(tmp_path: Path) -> None:
    content = b"A" * 10240
    file_path = tmp_path / "large_sample.bin"
    file_path.write_bytes(content)

    expected_hash = hashlib.sha256(content).hexdigest()
    actual_hash = compute_file_sha256(file_path, chunk_size=64)

    assert actual_hash == expected_hash


def test_missing_file_raises_exception(tmp_path: Path) -> None:
    missing_path = tmp_path / "does_not_exist.raw"

    with pytest.raises(FileNotFoundError, match="Evidence file not found"):
        compute_file_sha256(missing_path)


def test_directory_path_raises_exception(tmp_path: Path) -> None:
    with pytest.raises(FileNotFoundError, match="Evidence file not found"):
        compute_file_sha256(tmp_path)


def test_permission_error_handling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = tmp_path / "unreadable.bin"
    file_path.write_bytes(b"data")

    def mock_open(*args: object, **kwargs: object) -> None:
        raise PermissionError("Access denied")

    monkeypatch.setattr(Path, "open", mock_open)

    with pytest.raises(PermissionError, match="Permission denied reading evidence file"):
        compute_file_sha256(file_path)


def test_os_error_handling(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    file_path = tmp_path / "corrupt.bin"
    file_path.write_bytes(b"data")

    def mock_open(*args: object, **kwargs: object) -> None:
        raise OSError("I/O failure")

    monkeypatch.setattr(Path, "open", mock_open)

    with pytest.raises(OSError, match="Failed to read evidence file"):
        compute_file_sha256(file_path)
