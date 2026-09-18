from __future__ import annotations

import os
from pathlib import Path

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
