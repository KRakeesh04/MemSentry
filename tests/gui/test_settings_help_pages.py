from __future__ import annotations

import os

from PySide6.QtCore import QSettings
from PySide6.QtWidgets import QLabel

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


def test_settings_page_theme_switch_and_save(qtbot, qapp, tmp_path, monkeypatch):
    from memsentry.gui.theme import THEME_DARK, THEME_LIGHT, is_dark_theme, workspace_stylesheet

    settings_file = str(tmp_path / "theme_settings.ini")
    monkeypatch.setattr(
        "memsentry.gui.pages.settings.QSettings",
        lambda *_: QSettings(settings_file, QSettings.Format.IniFormat),
    )

    page = SettingsPage()
    qtbot.addWidget(page)

    assert page.theme_choice.count() >= 2
    light_index = page.theme_choice.findData(THEME_LIGHT)
    assert light_index >= 0

    # Switch to Light Theme
    page.theme_choice.setCurrentIndex(light_index)
    assert not is_dark_theme()
    assert "#F1F5F9" in workspace_stylesheet()

    page.save_button.click()
    assert "saved successfully" in page.status_message.text()

    ini_settings = QSettings(settings_file, QSettings.Format.IniFormat)
    assert ini_settings.value("appearance/theme") == THEME_LIGHT

    # Re-open page to verify persistence
    reloaded_page = SettingsPage()
    qtbot.addWidget(reloaded_page)
    assert reloaded_page.theme_choice.currentData() == THEME_LIGHT

    # Switch back to Dark Theme
    dark_index = page.theme_choice.findData(THEME_DARK)
    assert dark_index >= 0
    page.theme_choice.setCurrentIndex(dark_index)
    assert is_dark_theme()
    assert "#11151C" in workspace_stylesheet()

    page.save_button.click()
    assert ini_settings.value("appearance/theme") == THEME_DARK


def test_settings_page_reporting_defaults_and_save(qtbot, tmp_path, monkeypatch):
    settings_file = str(tmp_path / "reporting_settings.ini")
    monkeypatch.setattr(
        "memsentry.gui.pages.settings.QSettings",
        lambda *_: QSettings(settings_file, QSettings.Format.IniFormat),
    )

    page = SettingsPage()
    qtbot.addWidget(page)

    assert page.report_format_choice.count() == 3
    both_idx = page.report_format_choice.findData("both")
    assert both_idx >= 0

    page.report_format_choice.setCurrentIndex(both_idx)
    target_dir = str(tmp_path / "default_reports")
    page.report_output_input.setText(target_dir)

    page.save_button.click()
    assert "saved successfully" in page.status_message.text()

    ini_settings = QSettings(settings_file, QSettings.Format.IniFormat)
    assert ini_settings.value("reporting/format") == "both"
    assert ini_settings.value("reporting/output_directory") == target_dir

    # Verify reloading
    reloaded_page = SettingsPage()
    qtbot.addWidget(reloaded_page)
    assert reloaded_page.report_format_choice.currentData() == "both"
    assert reloaded_page.report_output_input.text() == target_dir


def test_help_page_renders_diagnostics(qtbot):
    page = HelpPage()
    qtbot.addWidget(page)

    assert "Help & Documentation" in page.findChild(object, "pageTitle").text()
    page_text = " ".join(lbl.text() for lbl in page.findChildren(object, "sectionTitle"))
    assert "Case Setup & Intake" in page_text
    assert "Baseline Verification" in page_text
    assert "Volatility 3 Analysis" in page_text
    assert "Correlation & Findings" in page_text

    all_labels = " ".join(lbl.text() for lbl in page.findChildren(QLabel))
    assert "RESTRICTED FORENSIC SYSTEM" in all_labels
    assert "AUTHORIZED OFFICERS ONLY" in all_labels


def test_main_window_settings_and_help_navigation(qtbot):
    window = MainWindow()
    qtbot.addWidget(window)

    # Index 8 is Settings, Index 9 is Help
    window.sidebar.setCurrentRow(8)
    assert window.pages.currentIndex() == 8

    window.sidebar.setCurrentRow(9)
    assert window.pages.currentIndex() == 9
