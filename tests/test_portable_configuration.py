import os
import shutil
import sys
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from PySide6.QtCore import QSettings

from memsentry.app.bootstrap import configure_portable_settings, load_portable_configuration
from memsentry.gui.analysis_dialog import AnalysisDialog
from memsentry.gui.pages.cases import CasesPage
from memsentry.gui.pages.evidence import EvidencePage
from memsentry.volatility.plugin_registry import PluginRegistry

ASSETS = Path(__file__).resolve().parents[1] / "packaging/portable"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    monkeypatch.setattr(os, "environ", os.environ.copy())


def test_portable_paths_follow_moved_folder(tmp_path, monkeypatch):
    root = tmp_path / "original"
    workspace = root / "MemSentryCases"
    workspace.mkdir(parents=True)
    shutil.copy2(ASSETS / "env", workspace / "env")
    moved = tmp_path / "Moved USB with spaces"
    root.rename(moved)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "executable", str(moved / "Linux" / "MemSentry"))
    monkeypatch.delenv("MEMSENTRY_ENV_FILE", raising=False)
    for key in (
        "MEMSENTRY_WORKSPACE", "MEMSENTRY_SYMBOLS", "MEMSENTRY_RULES",
        "MEMSENTRY_AVML", "MEMSENTRY_WINPMEM", "MEMSENTRY_PORTABLE",
    ):
        monkeypatch.delenv(key, raising=False)
    load_portable_configuration()
    workspace = moved / "MemSentryCases"
    assert os.environ["MEMSENTRY_WORKSPACE"] == str(workspace)
    assert os.environ["MEMSENTRY_SYMBOLS"] == str(workspace / "symbols")
    assert os.environ["MEMSENTRY_RULES"] == str(workspace / "Rules")
    assert os.environ["MEMSENTRY_AVML"] == str(workspace / "dump_tools/avml")
    assert os.environ["MEMSENTRY_WINPMEM"] == str(
        workspace / "dump_tools/go-winpmem_amd64_1.0-rc2_signed.exe"
    )


def test_explicit_configuration_keeps_precedence(tmp_path, monkeypatch):
    config = tmp_path / "custom.env"
    config.write_text("MEMSENTRY_WORKSPACE=./custom\n", encoding="utf-8")
    monkeypatch.setenv("MEMSENTRY_ENV_FILE", str(config))
    monkeypatch.delenv("MEMSENTRY_WORKSPACE", raising=False)
    load_portable_configuration()
    assert os.environ["MEMSENTRY_WORKSPACE"] == str(tmp_path / "custom")


def test_portable_settings_use_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("MEMSENTRY_PORTABLE", "1")
    monkeypatch.setenv("MEMSENTRY_WORKSPACE", str(tmp_path))
    calls = []
    monkeypatch.setattr(QSettings, "setDefaultFormat", lambda value: calls.append(value))
    monkeypatch.setattr(QSettings, "setPath", lambda *args: calls.append(args))
    configure_portable_settings()
    assert (tmp_path / "settings").is_dir()
    assert calls == [
        QSettings.Format.IniFormat,
        (QSettings.Format.IniFormat, QSettings.Scope.UserScope, str(tmp_path / "settings")),
    ]


def test_portable_mode_requires_workspace(monkeypatch):
    monkeypatch.setenv("MEMSENTRY_PORTABLE", "1")
    monkeypatch.delenv("MEMSENTRY_WORKSPACE", raising=False)
    with pytest.raises(ValueError, match="MEMSENTRY_WORKSPACE"):
        configure_portable_settings()


def test_pages_use_portable_workspace_and_rules(qtbot, tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    rules = tmp_path / "Rules"
    rules.mkdir()
    rule = rules / "test.yara"
    rule.write_text("rule test { condition: false }", encoding="utf-8")
    monkeypatch.setenv("MEMSENTRY_WORKSPACE", str(workspace))
    monkeypatch.setenv("MEMSENTRY_RULES", str(rules))
    monkeypatch.setenv("MEMSENTRY_SYMBOLS", str(workspace / "symbols"))
    settings = QSettings(str(tmp_path / "settings.ini"), QSettings.Format.IniFormat)
    settings.setValue("intake/workspace", str(tmp_path / "old-workspace"))
    for module in ("cases", "evidence"):
        monkeypatch.setattr(f"memsentry.gui.pages.{module}.QSettings", lambda *_: settings)
    for page_type in (CasesPage, EvidencePage):
        page = page_type()
        qtbot.addWidget(page)
        assert page.workspace.text() == str(workspace)
    registry = PluginRegistry(discovered_plugins={"windows.pslist.PsList": object})
    monkeypatch.setattr("memsentry.gui.analysis_dialog.PluginRegistry", lambda: registry)
    evidence = SimpleNamespace(id=uuid4(), evidence_os="windows", original_filename="test.mem")
    dialog = AnalysisDialog(str(workspace), evidence)
    qtbot.addWidget(dialog)
    qtbot.waitUntil(lambda: not dialog.catalog.isRunning())
    assert dialog.rule_paths == [rule]
    assert dialog.symbols.text() == str(workspace / "symbols")
