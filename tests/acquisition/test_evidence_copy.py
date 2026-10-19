from types import SimpleNamespace

import pytest

from memsentry.app.evidence_copy import COPY_RESERVE_BYTES, check_copy_space, copy_image


def test_copy_never_overwrites_destination(tmp_path):
    source = tmp_path / "source.mem"
    source.write_bytes(b"synthetic source")
    destination = tmp_path / "existing.mem"
    destination.write_bytes(b"existing evidence")
    with pytest.raises(FileExistsError):
        copy_image(source, destination, source.stat().st_size, lambda: None, lambda *_: None)
    assert destination.read_bytes() == b"existing evidence"


@pytest.mark.parametrize("size", [2, 100])
def test_copy_detects_source_size_change(tmp_path, size):
    source = tmp_path / "source.mem"
    source.write_bytes(b"synthetic source")
    with pytest.raises(ValueError, match="Evidence changed during copying"):
        copy_image(source, tmp_path / "copy.partial", size, lambda: None, lambda *_: None)


def test_space_check_includes_reserve_and_exact_boundary(tmp_path, monkeypatch):
    required = 100 + COPY_RESERVE_BYTES
    monkeypatch.setattr(
        "memsentry.app.evidence_copy.shutil.disk_usage", lambda _: SimpleNamespace(free=required)
    )
    assert check_copy_space(tmp_path, 100) == (required, required)
    with pytest.raises(ValueError, match="Insufficient free space"):
        check_copy_space(tmp_path, 101)
