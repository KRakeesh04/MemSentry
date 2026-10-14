from __future__ import annotations

import os

from PySide6.QtCore import QSettings

from memsentry.gui.main_window import MainWindow
from memsentry.gui.pages.help import HelpPage
from memsentry.gui.pages.settings import SettingsPage


def test_settings_page_loads_and_saves(qtbot, tmp_path, monkeypatch):
    settings_file = str(tmp_path / "test_settings.ini")
    monkeypatch.setattr(
        "memsentry.gui.pages.settings.QSettings",
        lambda *_: QSettings(settings_file, QSettings.Format.IniFormat),
    )

    page = SettingsPage()
    qtbot.addWidget(page)

    page.workspace_input.setText(str(tmp_path / "workspace"))
    page.symbols_input.setText(str(tmp_path / "symbols"))
    page.save_button.click()

    assert "saved successfully" in page.status_message.text()
    assert os.environ.get("MEMSENTRY_SYMBOLS") == str(tmp_path / "symbols")

    # Cleanup env
    if "MEMSENTRY_SYMBOLS" in os.environ:
        del os.environ["MEMSENTRY_SYMBOLS"]


def test_help_page_renders_diagnostics(qtbot):
    page = HelpPage()
    qtbot.addWidget(page)

    assert "Help & Documentation" in page.findChild(object, "pageTitle").text()


def test_main_window_settings_and_help_navigation(qtbot):
    window = MainWindow()
    qtbot.addWidget(window)

    # Index 8 is Settings, Index 9 is Help
    window.sidebar.setCurrentRow(8)
    assert window.pages.currentIndex() == 8

    window.sidebar.setCurrentRow(9)
    assert window.pages.currentIndex() == 9
