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

from memsentry.acquisition.config import load_environment_file
from memsentry.acquisition.tool_catalog import available_tools
from memsentry.version import __version__


class SettingsPage(QScrollArea):
    """Application preferences and environment configuration page."""

    settings_changed = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
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
            "Manage workspace defaults, forensic symbols, acquisition tools, and scanner configurations."
        )
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        self.status_message = QLabel("")
        self.status_message.setWordWrap(True)
        self.status_message.setObjectName("muted")
        layout.addWidget(self.status_message)

        # Section 1: Workspace & Storage
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

        # Section 2: Forensic Symbols & Volatility
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

        symbols_path = os.environ.get("MEMSENTRY_SYMBOLS", "")
        self.symbols_input.setText(symbols_path)

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
            status_text = "Available" if tool.available else "Not Found / Not Configured"
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

        symbols_path = self.symbols_input.text().strip()
        if symbols_path:
            os.environ["MEMSENTRY_SYMBOLS"] = symbols_path
        elif "MEMSENTRY_SYMBOLS" in os.environ:
            del os.environ["MEMSENTRY_SYMBOLS"]

        self.status_message.setText("Settings saved successfully.")
        self.settings_changed.emit()

    def _browse_workspace(self) -> None:
        path = QFileDialog.getExistingDirectory(
            self, "Select Default Workspace Folder", self.workspace_input.text()
        )
        if path:
            self.workspace_input.setText(path)

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
                load_environment_file(path)
                self.refresh()
                self.status_message.setText(f"Loaded configuration from {Path(path).name}")
            except Exception as exc:
                self.status_message.setText(f"Could not load env file: {exc}")


def create_page() -> SettingsPage:
    return SettingsPage()
