"""Plugin selection and background analysis workers."""

import importlib.util
import os
from pathlib import Path

from PySide6.QtCore import QEvent, QObject, Qt, QThread, Signal
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import (
    QCheckBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from memsentry.app.analysis_job import AnalysisRequest, run_analysis
from memsentry.gui.controls import ThemedComboBox
from memsentry.gui.cursors import InteractiveCursors
from memsentry.models.evidence import Evidence
from memsentry.volatility.plugin_registry import PluginRegistry
from memsentry.volatility.plugin_runner import PARSER_SPECS


class CatalogWorker(QThread):
    ready = Signal(object)
    failed = Signal(str)

    def run(self) -> None:
        try:
            self.ready.emit(PluginRegistry())
        except Exception as exc:
            self.failed.emit(f"Plugin discovery failed: {exc}")


class AnalysisWorker(QThread):
    started_run = Signal(object)
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, request: AnalysisRequest, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.request = request

    def run(self) -> None:
        try:
            self.succeeded.emit(run_analysis(self.request, self.started_run.emit))
        except Exception as exc:
            self.failed.emit(str(exc))


class AnalysisDialog(QDialog):
    def __init__(self, workspace: str, evidence: Evidence, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("analysisDialog")
        self.workspace = workspace
        self.evidence = evidence
        self.registry: PluginRegistry | None = None
        self.request: AnalysisRequest | None = None
        self.rule_paths: list[Path] = []
        self.setWindowTitle("Analyze memory evidence")
        self.resize(680, 690)
        layout = QVBoxLayout(self)
        title = QLabel("Choose analysis plugins")
        title.setObjectName("sectionTitle")
        layout.addWidget(title)
        name = QLabel(evidence.original_filename)
        name.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(name)
        note = QLabel(
            "Evidence stays read-only. SHA-256 is verified before and after analysis. "
            "Analysis runs in the background; closing the app is blocked until it finishes."
        )
        note.setWordWrap(True)
        layout.addWidget(note)
        form = QFormLayout()
        self.os_choice = ThemedComboBox()
        self.os_choice.addItem("Choose image OS…", None)
        self.os_choice.addItem("Windows", "windows")
        self.os_choice.addItem("Linux", "linux")
        if evidence.evidence_os:
            index = self.os_choice.findData(str(evidence.evidence_os))
            self.os_choice.setCurrentIndex(max(0, index))
            self.os_choice.setEnabled(False)
        form.addRow("Image OS", self.os_choice)
        self.symbols = QLineEdit(
            os.environ.get("MEMSENTRY_SYMBOLS", str(Path(workspace) / "symbols"))
        )
        symbol_row = QHBoxLayout()
        symbol_row.addWidget(self.symbols)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._symbols)
        symbol_row.addWidget(browse)
        form.addRow("Symbols root", symbol_row)
        layout.addLayout(form)
        hint = QLabel(
            "The symbols root directory where Volatility 3 ISF symbols for windows/ or linux/ are stored or automatically fetched."
        )
        hint.setWordWrap(True)
        hint.setObjectName("muted")
        layout.addWidget(hint)
        self.plugins = QListWidget()
        self.plugins.setAccessibleName("Available analysis plugins")
        self.plugins.setMouseTracking(True)
        self.plugins.viewport().installEventFilter(self)
        layout.addWidget(self.plugins, 1)
        self.yara = QCheckBox("Run YARA using the selected rules")
        layout.addWidget(self.yara)
        self.rules = QLineEdit()
        self.rules.setReadOnly(True)
        self.rules.setPlaceholderText("No rules selected")
        rules_row = QHBoxLayout()
        rules_row.addWidget(self.rules)
        self.rules_button = QPushButton("Choose rules…")
        self.rules_button.clicked.connect(self._rules)
        rules_row.addWidget(self.rules_button)
        layout.addLayout(rules_row)
        from memsentry.resource_paths import resource_directory

        bundled = resource_directory() / "yara"
        self.rule_paths = sorted(bundled.glob("*.yar")) + sorted(bundled.glob("*.yara"))
        self.rules.setText("; ".join(str(path) for path in self.rule_paths))
        yara_available = importlib.util.find_spec("yara") is not None
        self.yara.setEnabled(yara_available)
        self.rules_button.setEnabled(yara_available)
        self.yara.setChecked(yara_available and bool(self.rule_paths))
        yara_hint = QLabel(
            "YARA requires selected .yar/.yara rules. If unchecked, the run records 'not requested'."
            if yara_available
            else "YARA unavailable: install the optional yara-python dependency to enable scanning."
        )
        yara_hint.setWordWrap(True)
        layout.addWidget(yara_hint)
        self.message = QLabel("Discovering approved local plugins…")
        self.message.setWordWrap(True)
        self.message.setTextFormat(Qt.TextFormat.PlainText)
        layout.addWidget(self.message)
        self.buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setText("Start analysis")
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        self.buttons.accepted.connect(self._accept)
        self.buttons.rejected.connect(self.reject)
        layout.addWidget(self.buttons)
        self.os_choice.currentIndexChanged.connect(self._populate)
        self.catalog = CatalogWorker(self)
        self.catalog.ready.connect(self._catalog_ready)
        self.catalog.failed.connect(self.message.setText)
        self._interactive_cursors = InteractiveCursors(self)
        self.catalog.start()

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if watched is self.plugins.viewport():
            if isinstance(event, QMouseEvent) and event.type() == QEvent.Type.MouseMove:
                item = self.plugins.itemAt(event.position().toPoint())
                actionable = (
                    self.plugins.isEnabled() and item is not None
                    and bool(item.flags() & Qt.ItemFlag.ItemIsEnabled)
                    and bool(item.flags() & Qt.ItemFlag.ItemIsUserCheckable)
                )
                self.plugins.viewport().setCursor(
                    Qt.CursorShape.PointingHandCursor if actionable else Qt.CursorShape.ArrowCursor)
            elif event.type() in (QEvent.Type.Leave, QEvent.Type.EnabledChange):
                self.plugins.viewport().setCursor(Qt.CursorShape.ArrowCursor)
        return super().eventFilter(watched, event)

    def _catalog_ready(self, registry: PluginRegistry) -> None:
        self.registry = registry
        self._populate()

    def _populate(self) -> None:
        self.plugins.clear()
        os_type = self.os_choice.currentData()
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(False)
        if not self.registry or not os_type:
            self.message.setText("Choose the operating system contained in this image.")
            return
        available = self.registry.available_plugins(os_type)
        for plugin in available:
            item = QListWidgetItem(
                f"{plugin.display_name} — {plugin.volatility_plugin_for(os_type)}"
            )
            item.setData(Qt.ItemDataRole.UserRole, plugin.id)
            item.setToolTip(plugin.description)
            if plugin.parser in PARSER_SPECS:
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                item.setCheckState(
                    Qt.CheckState.Checked if plugin.default_enabled else Qt.CheckState.Unchecked
                )
            else:
                item.setFlags(Qt.ItemFlag.NoItemFlags)
                item.setToolTip("Parser not implemented; this plugin cannot be selected.")
            self.plugins.addItem(item)
        unavailable = self.registry.unavailable_plugins(os_type)
        self.message.setText(
            f"{len(available)} available plugins. "
            + (
                "Unavailable: " + ", ".join(p.display_name for p in unavailable)
                if unavailable
                else "Choose the checks to run."
            )
        )
        self.buttons.button(QDialogButtonBox.StandardButton.Ok).setEnabled(bool(available))

    def _symbols(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose symbols root", self.symbols.text())
        if path:
            self.symbols.setText(path)

    def _rules(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Choose approved YARA rules", "", "YARA rules (*.yar *.yara)"
        )
        if paths:
            self.rule_paths = [Path(path) for path in paths]
            self.rules.setText("; ".join(paths))
            self.yara.setChecked(True)

    def _accept(self) -> None:
        ids = tuple(
            self.plugins.item(index).data(Qt.ItemDataRole.UserRole)
            for index in range(self.plugins.count())
            if self.plugins.item(index).checkState() == Qt.CheckState.Checked
        )
        if not ids:
            self.message.setText("Select at least one available plugin.")
            return
        os_type = self.os_choice.currentData()
        root = Path(self.symbols.text()).expanduser()
        if self.yara.isChecked() and not self.rule_paths:
            self.message.setText("Select at least one YARA rule file.")
            return
        self.request = AnalysisRequest(
            self.workspace,
            self.evidence.id,
            os_type,
            ids,
            root,
            tuple(self.rule_paths) if self.yara.isChecked() else (),
        )
        if not self.catalog.isRunning():
            self.accept()

    def reject(self) -> None:
        if self.catalog.isRunning():
            self.message.setText("Please wait for plugin discovery to finish before closing.")
            return
        super().reject()
