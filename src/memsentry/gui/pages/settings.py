"""Settings page for configuring workspace paths, acquisition tools, and symbols."""

from __future__ import annotations

import importlib.util
import os
from pathlib import Path

from PySide6.QtCore import QSettings, Signal
from PySide6.QtWidgets import (
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)
from volatility3.framework import constants

from memsentry.acquisition.tool_catalog import available_tools
from memsentry.gui.acquisition_settings import import_tool_settings, restore_tool_settings
from memsentry.gui.controls import ThemedComboBox
from memsentry.gui.theme import (
    THEME_DARK,
    THEME_LIGHT,
    THEME_SYSTEM,
    apply_theme,
    get_saved_theme,
    save_theme,
)
from memsentry.version import __version__


class SettingsPage(QScrollArea):
    """Application preferences and environment configuration page."""

    settings_changed = Signal()
    tool_configuration_changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._loading_settings = False
        restore_tool_settings()
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(24)

        # Header
        heading = QHBoxLayout()
        title = QLabel("Settings")
        title.setObjectName("pageTitle")
        heading.addWidget(title)
        heading.addStretch()
        self.save_button = QPushButton("Save settings")
        self.save_button.clicked.connect(self.save_settings)
        heading.addWidget(self.save_button)
        layout.addLayout(heading)

        subtitle = QLabel(
            "Manage interface theme, workspace defaults, forensic symbols, acquisition tools, and scanner configurations."
        )
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        self.status_message = QLabel("")
        self.status_message.setWordWrap(True)
        self.status_message.setObjectName("muted")
        layout.addWidget(self.status_message)

        # Section 1: Appearance & Theme
        theme_card, theme_box = self._create_card("Appearance & Theme")
        theme_desc = QLabel(
            "Select your preferred visual style. You can switch between Dark and Light mode, or follow your operating system default."
        )
        theme_desc.setObjectName("muted")
        theme_desc.setWordWrap(True)
        theme_box.addWidget(theme_desc)

        theme_form = QFormLayout()
        theme_form.setSpacing(12)

        self.theme_choice = ThemedComboBox()
        self.theme_choice.addItem("Dark Theme", THEME_DARK)
        self.theme_choice.addItem("Light Theme", THEME_LIGHT)
        self.theme_choice.addItem("System Default", THEME_SYSTEM)
        self.theme_choice.currentIndexChanged.connect(self._theme_selection_changed)

        theme_form.addRow("Interface Theme", self.theme_choice)
        theme_box.addLayout(theme_form)
        layout.addWidget(theme_card)

        # Section 2: Workspace & Storage
        ws_card, ws_box = self._create_card("Workspace & Storage")
        ws_form = QFormLayout()
        ws_form.setSpacing(12)

        self.workspace_input = QLineEdit()
        self.workspace_input.setPlaceholderText("Select default workspace directory...")
        ws_row = QHBoxLayout()
        ws_row.addWidget(self.workspace_input)
        ws_browse = QPushButton("Browse…")
        ws_browse.clicked.connect(self._browse_workspace)
        ws_row.addWidget(ws_browse)
        ws_form.addRow("Default Workspace Path", ws_row)
        ws_box.addLayout(ws_form)
        layout.addWidget(ws_card)

        # Section 3: Reporting
        rpt_card, rpt_box = self._create_card("Reporting")
        rpt_desc = QLabel(
            "Configure default report formats and default destination directory for case reports."
        )
        rpt_desc.setObjectName("muted")
        rpt_desc.setWordWrap(True)
        rpt_box.addWidget(rpt_desc)

        rpt_form = QFormLayout()
        rpt_form.setSpacing(12)

        self.report_format_choice = ThemedComboBox()
        self.report_format_choice.addItem("Both (HTML & JSON)", "both")
        self.report_format_choice.addItem("HTML (Readable report)", "html")
        self.report_format_choice.addItem("JSON (Structured results)", "json")
        rpt_form.addRow("Default Format", self.report_format_choice)

        self.report_output_input = QLineEdit()
        self.report_output_input.setPlaceholderText("Select default directory for generated reports...")
        rpt_row = QHBoxLayout()
        rpt_row.addWidget(self.report_output_input)
        rpt_browse = QPushButton("Browse…")
        rpt_browse.clicked.connect(self._browse_report_output)
        rpt_row.addWidget(rpt_browse)
        rpt_form.addRow("Default Output Path", rpt_row)

        rpt_box.addLayout(rpt_form)
        layout.addWidget(rpt_card)

        # Section 4: Forensic Symbols & Volatility
        sym_card, sym_box = self._create_card("Volatility 3 & Symbol Tables")
        sym_form = QFormLayout()
        sym_form.setSpacing(12)

        sym_form.addRow("Volatility 3 Version", QLabel(constants.PACKAGE_VERSION))
        self.symbols_input = QLineEdit()
        self.symbols_input.setPlaceholderText("Path to symbols root (must contain windows/ or linux/)...")
        sym_row = QHBoxLayout()
        sym_row.addWidget(self.symbols_input)
        sym_browse = QPushButton("Browse…")
        sym_browse.clicked.connect(self._browse_symbols)
        sym_row.addWidget(sym_browse)
        sym_form.addRow("Custom Symbols Directory", sym_row)
        sym_box.addLayout(sym_form)
        layout.addWidget(sym_card)

        # Section 3: Acquisition Tools Status
        tools_card, tools_box = self._create_card("Memory Acquisition Tools")

        tools_header = QHBoxLayout()
        tools_desc = QLabel("Status of configured acquisition executables (AVML, WinPmem, DumpIt, LiME).")
        tools_desc.setObjectName("muted")
        tools_header.addWidget(tools_desc, 1)
        load_env_btn = QPushButton("Load .env File…")
        load_env_btn.clicked.connect(self._load_env_file)
        tools_header.addWidget(load_env_btn)
        tools_box.addLayout(tools_header)

        self.tools_layout = QVBoxLayout()
        self.tools_layout.setSpacing(8)
        tools_box.addLayout(self.tools_layout)
        layout.addWidget(tools_card)

        # Section 4: YARA & Diagnostics
        yara_card, yara_box = self._create_card("YARA & Platform Diagnostics")
        yara_form = QFormLayout()
        yara_form.setSpacing(12)

        yara_spec = importlib.util.find_spec("yara")
        yara_installed = yara_spec is not None
        yara_status = "Available (yara-python)" if yara_installed else "Not installed"
        yara_label = QLabel(yara_status)
        yara_form.addRow("YARA Engine", yara_label)
        yara_form.addRow("MemSentry Core Version", QLabel(__version__))
        yara_box.addLayout(yara_form)
        layout.addWidget(yara_card)

        layout.addStretch()
        self.setWidget(content)

        self.refresh()

    def _create_card(self, title_text: str) -> tuple[QFrame, QVBoxLayout]:
        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 16, 20, 16)
        card_layout.setSpacing(12)

        title = QLabel(title_text)
        title.setObjectName("sectionTitle")
        card_layout.addWidget(title)
        return card, card_layout

    def refresh(self) -> None:
        """Reload configuration values from QSettings and system environment."""
        qsettings = QSettings("MemSentry", "MemSentry")
        default_ws = str(qsettings.value("intake/workspace", ""))
        self.workspace_input.setText(default_ws)

        self._loading_settings = True
        try:
            saved_theme = get_saved_theme(qsettings)
            index = self.theme_choice.findData(saved_theme)
            if index >= 0:
                self.theme_choice.setCurrentIndex(index)
            else:
                self.theme_choice.setCurrentIndex(0)
            apply_theme(saved_theme)
        finally:
            self._loading_settings = False

        symbols_path = os.environ.get("MEMSENTRY_SYMBOLS", "")
        self.symbols_input.setText(symbols_path)

        rpt_format = str(qsettings.value("reporting/format", "both")).lower().strip()
        idx = self.report_format_choice.findData(rpt_format)
        if idx >= 0:
            self.report_format_choice.setCurrentIndex(idx)
        else:
            self.report_format_choice.setCurrentIndex(0)

        rpt_output = str(qsettings.value("reporting/output_directory", ""))
        self.report_output_input.setText(rpt_output)

        # Refresh acquisition tools list
        while self.tools_layout.count():
            item = self.tools_layout.takeAt(0)
            widget = item.widget() if item else None
            if widget is not None:
                widget.deleteLater()

        for tool in available_tools():
            row = QFrame()
            row_layout = QHBoxLayout(row)
            row_layout.setContentsMargins(8, 4, 8, 4)

            name = QLabel(tool.name)
            status_text = tool.description
            status = QLabel(f"{tool.name} ({tool.host}) · {status_text}")
            status.setObjectName("muted" if not tool.available else "")

            row_layout.addWidget(name, 1)
            row_layout.addWidget(status)
            self.tools_layout.addWidget(row)

    def save_settings(self) -> None:
        """Persist settings to QSettings and environment variables."""
        ws_path = self.workspace_input.text().strip()
        qsettings = QSettings("MemSentry", "MemSentry")
        qsettings.setValue("intake/workspace", ws_path)

        theme_mode = self.theme_choice.currentData() or THEME_DARK
        save_theme(theme_mode, qsettings)
        apply_theme(theme_mode)

        rpt_format = self.report_format_choice.currentData() or "both"
        qsettings.setValue("reporting/format", rpt_format)

        rpt_output = self.report_output_input.text().strip()
        qsettings.setValue("reporting/output_directory", rpt_output)

        symbols_path = self.symbols_input.text().strip()
        if symbols_path:
            os.environ["MEMSENTRY_SYMBOLS"] = symbols_path
        elif "MEMSENTRY_SYMBOLS" in os.environ:
            del os.environ["MEMSENTRY_SYMBOLS"]

        self.status_message.setText("Settings saved successfully.")
        self.settings_changed.emit()

    def _theme_selection_changed(self, index: int) -> None:
        if getattr(self, "_loading_settings", False):
            return
        theme_mode = self.theme_choice.currentData()
        if theme_mode:
            apply_theme(theme_mode)

    def _browse_workspace(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self, "Select Default Workspace Folder", self.workspace_input.text()
        )
        if path:
            self.workspace_input.setText(path)

    def _browse_report_output(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self, "Select Default Report Output Folder", self.report_output_input.text()
        )
        if path:
            self.report_output_input.setText(path)

    def _browse_symbols(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self, "Select Custom Symbols Directory", self.symbols_input.text()
        )
        if path:
            self.symbols_input.setText(path)

    def _load_env_file(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select Environment File", "", "Environment files (*.env);;All files (*)"
        )
        if path:
            try:
                import_tool_settings(path)
                self.refresh()
                self.tool_configuration_changed.emit()
                self.status_message.setText(f"Loaded and saved configuration from {Path(path).name}")
            except Exception as exc:
                self.status_message.setText(f"Could not load env file: {exc}")


def create_page() -> SettingsPage:
    return SettingsPage()
