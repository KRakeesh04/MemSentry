from __future__ import annotations

import os
from pathlib import Path

import pytest

from memsentry.acquisition.config import load_environment_file


def test_load_environment_file_resolves_tool_paths_relative_to_file(
    tmp_path: Path,
    monkeypatch,
) -> None:
    config = tmp_path / ".env"
    config.write_text(
        "# acquisition tools\nexport MEMSENTRY_AVML=tools/avml\nMEMSENTRY_LOG_LEVEL='debug'\n",
        encoding="utf-8",
    )
    monkeypatch.delenv("MEMSENTRY_AVML", raising=False)
    monkeypatch.delenv("MEMSENTRY_LOG_LEVEL", raising=False)

    load_environment_file(config)

    assert os.environ["MEMSENTRY_AVML"] == str((tmp_path / "tools/avml").resolve())
    assert os.environ["MEMSENTRY_LOG_LEVEL"] == "debug"


def test_override_is_explicit_and_invalid_file_does_not_partially_apply(tmp_path, monkeypatch):
    monkeypatch.setenv("MEMSENTRY_AVML", "original")
    config = tmp_path / ".env"
    config.write_text("MEMSENTRY_AVML=./replacement\n")
    load_environment_file(config)
    assert os.environ["MEMSENTRY_AVML"] == "original"
    load_environment_file(config, override=True)
    replacement = str(tmp_path / "replacement")
    assert os.environ["MEMSENTRY_AVML"] == replacement
    config.write_text("MEMSENTRY_AVML=./bad\ninvalid line\n")
    with pytest.raises(ValueError):
        load_environment_file(config, override=True)
    assert os.environ["MEMSENTRY_AVML"] == replacement
