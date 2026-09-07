"""Analysis & Plugin Center view widget for configuring, running, and reviewing forensic analysis runs."""

from __future__ import annotations

import sys
from pathlib import Path
from uuid import UUID

from PySide6.QtCore import QObject, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QDesktopServices, QShowEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from memsentry.analysis.orchestrator import AnalysisOrchestrator
from memsentry.models.analysis_run import (
    AnalysisRun,
    AnalysisRunCreate,
    HostOS,
)
from memsentry.models.case import Case
from memsentry.models.evidence import Evidence
from memsentry.models.plugin_run import PluginRun, PluginRunCreate
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.version import __version__
from memsentry.volatility.plugin_applicability import (
    PluginApplicabilityService,
    PluginMetadata,
)


def get_current_host_os() -> HostOS:
    """Detect current operating system hosting MemSentry."""
    sys_plat = sys.platform.lower()
    if sys_plat.startswith("win"):
        return HostOS.WINDOWS
    if sys_plat.startswith("linux"):
        return HostOS.LINUX
    if sys_plat.startswith("darwin"):
        return HostOS.MACOS
    return HostOS.WINDOWS


class AnalysisWorker(QThread):
    """Background worker thread for running AnalysisOrchestrator without blocking the GUI event loop."""

    finished = Signal(object)  # Emits AnalysisRun model on completion
    failed = Signal(str)      # Emits error message string on failure

    def __init__(
        self,
        orchestrator: AnalysisOrchestrator,
        analysis_run_id: UUID,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.orchestrator = orchestrator
        self.analysis_run_id = analysis_run_id

    def run(self) -> None:
        try:
            result = self.orchestrator.execute_analysis_run(self.analysis_run_id)
            self.finished.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


class AnalysisView(QWidget):
    """View widget for configuring plugins, executing analysis runs, and reviewing run status history."""

    def __init__(
        self,
        evidence_repository: EvidenceRepository,
        analysis_run_repository: AnalysisRunRepository,
        plugin_run_repository: PluginRunRepository,
        plugin_applicability_service: type[
            PluginApplicabilityService
        ] = PluginApplicabilityService,
        analysis_orchestrator: AnalysisOrchestrator | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.evidence_repository = evidence_repository
        self.analysis_run_repository = analysis_run_repository
        self.plugin_run_repository = plugin_run_repository
        self.plugin_applicability_service = plugin_applicability_service
        self.analysis_orchestrator = analysis_orchestrator

        self.active_case: Case | None = None
        self.selected_evidence: Evidence | None = None
        self.evidence_records: list[Evidence] = []
        self.analysis_worker: AnalysisWorker | None = None
        self.current_running_analysis_id: UUID | None = None

        self.status_poll_timer = QTimer(self)
        self.status_poll_timer.setInterval(500)
        self.status_poll_timer.timeout.connect(self._poll_running_analysis_status)

        self._build_ui()
        self.update_case_state()

    def _build_ui(self) -> None:
        # Title and Subtitle
        self.title_label = QLabel("Analysis & Plugin Center")
        self.title_label.setObjectName("pageTitle")
        self.subtitle_label = QLabel(
            "Configure core Volatility plugins and track analysis run progress."
        )

        self.state_label = QLabel()
        self.state_label.setObjectName("stateLabel")

        # Evidence Picker Layout
        evidence_picker_layout = QHBoxLayout()
        evidence_picker_label = QLabel("Select Evidence:")
        self.evidence_combo = QComboBox()
        self.evidence_combo.currentIndexChanged.connect(self.on_evidence_changed)

        evidence_picker_layout.addWidget(evidence_picker_label)
        evidence_picker_layout.addWidget(self.evidence_combo, stretch=1)

        # Selected Evidence Information Card
        self.evidence_info_card = QLabel("No evidence selected")
        self.evidence_info_card.setWordWrap(True)
        self.evidence_info_card.setStyleSheet("font-size: 12px; color: #2D3748;")

        # Splitter (Left: Plugin Center, Right: Analysis Runs & Plugin Details)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left Panel: Plugin Selection
        left_container = QWidget()
        left_layout = QVBoxLayout(left_container)
        left_layout.setContentsMargins(0, 0, 0, 0)

        plugins_group = QGroupBox("Core Volatility Plugins")
        plugins_vbox = QVBoxLayout(plugins_group)

        self.plugins_status_label = QLabel("Select an evidence item to configure plugins.")

        # Select / Deselect All Actions
        select_actions_layout = QHBoxLayout()
        self.select_all_btn = QPushButton("Select All")
        self.select_all_btn.clicked.connect(self.select_all_plugins)
        self.deselect_all_btn = QPushButton("Deselect All")
        self.deselect_all_btn.clicked.connect(self.deselect_all_plugins)

        select_actions_layout.addWidget(self.select_all_btn)
        select_actions_layout.addWidget(self.deselect_all_btn)
        select_actions_layout.addStretch()

        self.plugins_list = QListWidget()

        # Run Analysis Action
        self.run_button = QPushButton("Run Analysis")
        self.run_button.setEnabled(False)
        self.run_button.setToolTip(
            "Stages analysis and executes configured plugins via AnalysisOrchestrator."
        )
        self.run_button.clicked.connect(self.run_analysis)

        plugins_vbox.addWidget(self.plugins_status_label)
        plugins_vbox.addLayout(select_actions_layout)
        plugins_vbox.addWidget(self.plugins_list)
        plugins_vbox.addWidget(self.run_button)

        left_layout.addWidget(plugins_group)
        splitter.addWidget(left_container)

        # Right Panel: Analysis History & Plugin Runs Details
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)

        # Analysis Runs Table Group
        runs_group = QGroupBox("Analysis Runs History")
        runs_vbox = QVBoxLayout(runs_group)

        self.runs_table = QTableWidget(0, 5)
        self.runs_table.setHorizontalHeaderLabels(
            ["Created", "Status", "Host OS", "Volatility Ver.", "Error"]
        )
        self.runs_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.runs_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.runs_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.runs_table.setSortingEnabled(True)
        self.runs_table.itemSelectionChanged.connect(self.on_analysis_run_selected)
        self.runs_table.horizontalHeader().setStretchLastSection(True)

        runs_vbox.addWidget(self.runs_table)

        # Plugin Run Status Group
        plugin_runs_group = QGroupBox("Plugin Execution Statuses")
        plugin_vbox = QVBoxLayout(plugin_runs_group)

        self.plugin_runs_table = QTableWidget(0, 4)
        self.plugin_runs_table.setHorizontalHeaderLabels(
            ["Plugin Name", "Status", "Started", "Completed / Error"]
        )
        self.plugin_runs_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.plugin_runs_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.plugin_runs_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.plugin_runs_table.horizontalHeader().setStretchLastSection(True)
        self.plugin_runs_table.itemSelectionChanged.connect(
            self.on_plugin_run_selected
        )
        self.plugin_runs_table.cellDoubleClicked.connect(
            self.open_selected_plugin_output
        )

        plugin_actions_layout = QHBoxLayout()
        self.view_output_btn = QPushButton("View Output")
        self.view_output_btn.setEnabled(False)
        self.view_output_btn.setToolTip("Open the generated plugin output JSON file.")
        self.view_output_btn.clicked.connect(self.open_selected_plugin_output)

        plugin_actions_layout.addStretch()
        plugin_actions_layout.addWidget(self.view_output_btn)

        plugin_vbox.addWidget(self.plugin_runs_table)
        plugin_vbox.addLayout(plugin_actions_layout)

        right_layout.addWidget(runs_group)
        right_layout.addWidget(plugin_runs_group)
        splitter.addWidget(right_container)

        splitter.setSizes([500, 500])

        # Main Layout
        layout = QVBoxLayout(self)
        layout.addWidget(self.title_label)
        layout.addWidget(self.subtitle_label)
        layout.addLayout(evidence_picker_layout)
        layout.addWidget(self.evidence_info_card)
        layout.addWidget(self.state_label)
        layout.addWidget(splitter)

    def set_active_case(self, case: Case | None) -> None:
        """Set active case context and update evidence items."""
        self.active_case = case
        self.update_case_state()

    def update_case_state(self) -> None:
        """Update UI based on active case presence."""
        self.evidence_combo.blockSignals(True)
        self.evidence_combo.clear()
        self.evidence_records.clear()
        self.selected_evidence = None

        if self.active_case is None:
            self.evidence_combo.setEnabled(False)
            self.state_label.setText(
                "No case opened. Select or open a case to configure and view analysis."
            )
            self.clear_all_views()
            self.evidence_combo.blockSignals(False)
            return

        self.evidence_combo.setEnabled(True)
        self.load_evidence_for_case()
        self.evidence_combo.blockSignals(False)

    def showEvent(self, event: QShowEvent) -> None:
        """Refresh evidence list whenever AnalysisView is shown."""
        super().showEvent(event)
        if self.active_case is not None:
            self.load_evidence_for_case()

    def load_evidence_for_case(self) -> None:
        """Fetch registered evidence files for the active case."""
        if self.active_case is None:
            return

        self.evidence_combo.blockSignals(True)
        self.evidence_combo.clear()
        self.evidence_records.clear()
        self.selected_evidence = None

        self.state_label.setText("Loading evidence for case...")
        try:
            records = self.evidence_repository.list_by_case(self.active_case.id)
        except Exception as exc:
            self.state_label.setText(f"Unable to load evidence: {exc}")
            self.clear_all_views()
            self.evidence_combo.blockSignals(False)
            return

        self.evidence_records = records

        if not records:
            self.state_label.setText(
                "No evidence registered for this case yet. Register evidence in the Evidence tab first."
            )
            self.clear_all_views()
            self.evidence_combo.blockSignals(False)
            return

        self.state_label.setText(f"{len(records)} evidence file(s) available")
        for evidence in records:
            os_str = (
                evidence.evidence_os.value.capitalize()
                if evidence.evidence_os is not None
                else "Unknown"
            )
            label = f"{evidence.original_filename} ({os_str}, {evidence.file_size_bytes:,} B)"
            self.evidence_combo.addItem(label, evidence)

        self.evidence_combo.blockSignals(False)

        if self.evidence_combo.count() > 0:
            self.evidence_combo.setCurrentIndex(0)
            self.on_evidence_changed()

    def on_evidence_changed(self) -> None:
        """Handle change in evidence combo selection."""
        data = self.evidence_combo.currentData()
        if isinstance(data, Evidence):
            self.selected_evidence = data
            self.display_evidence_info(data)
            self.populate_applicable_plugins(data)
            self.load_analysis_history(data)
        else:
            self.selected_evidence = None
            self.clear_all_views()

    def display_evidence_info(self, evidence: Evidence) -> None:
        """Display summary card for the selected evidence file."""
        os_str = (
            evidence.evidence_os.value.capitalize()
            if evidence.evidence_os is not None
            else "Unknown"
        )
        self.evidence_info_card.setText(
            f"<b>Evidence:</b> {evidence.original_filename} | "
            f"<b>OS:</b> {os_str} | "
            f"<b>Size:</b> {evidence.file_size_bytes:,} bytes | "
            f"<b>Integrity:</b> {evidence.integrity_status.value.capitalize()} | "
            f"<b>SHA-256:</b> {evidence.sha256[:16]}..."
        )

    def populate_applicable_plugins(self, evidence: Evidence) -> None:
        """Populate checkable plugins list based on target OS."""
        self.plugins_list.clear()

        if evidence.evidence_os is None:
            self.plugins_status_label.setText(
                "Target OS is unknown. Select an OS for this evidence to configure plugins."
            )
            self.run_button.setEnabled(False)
            self.select_all_btn.setEnabled(False)
            self.deselect_all_btn.setEnabled(False)
            return

        plugins: list[PluginMetadata] = (
            self.plugin_applicability_service.get_available_plugins(
                evidence.evidence_os
            )
        )

        if not plugins:
            self.plugins_status_label.setText(
                f"No core plugins available for {evidence.evidence_os.value.capitalize()}."
            )
            self.run_button.setEnabled(False)
            self.select_all_btn.setEnabled(False)
            self.deselect_all_btn.setEnabled(False)
            return

        self.plugins_status_label.setText(
            f"Available Core Plugins ({len(plugins)}) for {evidence.evidence_os.value.capitalize()}:"
        )
        self.select_all_btn.setEnabled(True)
        self.deselect_all_btn.setEnabled(True)
        self.run_button.setEnabled(True)

        for plugin in plugins:
            item_text = (
                f"[{plugin.category.value.upper()}] {plugin.name} — {plugin.description}"
            )
            list_item = QListWidgetItem(item_text)
            list_item.setFlags(
                list_item.flags() | Qt.ItemFlag.ItemIsUserCheckable
            )
            list_item.setCheckState(Qt.CheckState.Checked)
            list_item.setData(Qt.ItemDataRole.UserRole, plugin)
            self.plugins_list.addItem(list_item)

    def select_all_plugins(self) -> None:
        for index in range(self.plugins_list.count()):
            item = self.plugins_list.item(index)
            if item is not None:
                item.setCheckState(Qt.CheckState.Checked)

    def deselect_all_plugins(self) -> None:
        for index in range(self.plugins_list.count()):
            item = self.plugins_list.item(index)
            if item is not None:
                item.setCheckState(Qt.CheckState.Unchecked)

    def get_selected_plugin_names(self) -> list[str]:
        """Return names of plugins currently checked in the list."""
        selected_names: list[str] = []
        for index in range(self.plugins_list.count()):
            item = self.plugins_list.item(index)
            if item is not None and item.checkState() == Qt.CheckState.Checked:
                plugin = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(plugin, PluginMetadata):
                    selected_names.append(plugin.name)
        return selected_names

    def run_analysis(self) -> None:
        """Stage pending AnalysisRun/PluginRun records and launch AnalysisWorker background thread."""
        if self.selected_evidence is None:
            self.state_label.setText("Please select an evidence file.")
            return

        if self.analysis_worker is not None and self.analysis_worker.isRunning():
            self.state_label.setText("An analysis run is already in progress.")
            return

        selected_plugins = self.get_selected_plugin_names()
        if not selected_plugins:
            self.state_label.setText(
                "Please select at least one plugin to include in the analysis run."
            )
            return

        try:
            host_os = get_current_host_os()
            analysis_create = AnalysisRunCreate(
                evidence_id=self.selected_evidence.id,
                application_version=__version__,
                volatility_version="3.0.0",
                host_os=host_os,
            )
            analysis_run = self.analysis_run_repository.create(analysis_create)

            for plugin_name in selected_plugins:
                plugin_create = PluginRunCreate(
                    analysis_run_id=analysis_run.id,
                    plugin_name=plugin_name,
                    configuration={},
                )
                self.plugin_run_repository.create(plugin_create)

        except Exception as exc:
            self.state_label.setText(f"Could not create analysis run: {exc}")
            return

        if self.analysis_orchestrator is not None:
            # Disable UI controls during background execution
            self._set_controls_enabled(False)
            self.state_label.setText(
                f"Running analysis {str(analysis_run.id)[:8]} ({len(selected_plugins)} plugins)... Please wait."
            )
            self.load_analysis_history(self.selected_evidence)
            self.select_analysis_run(analysis_run.id)

            self.current_running_analysis_id = analysis_run.id
            if not self.status_poll_timer.isActive():
                self.status_poll_timer.start()

            # Create and launch background worker thread
            self.analysis_worker = AnalysisWorker(
                self.analysis_orchestrator, analysis_run.id, self
            )
            self.analysis_worker.finished.connect(self._on_analysis_finished)
            self.analysis_worker.failed.connect(self._on_analysis_failed)
            self.analysis_worker.start()
        else:
            # Staging-only fallback mode
            self.state_label.setText(
                f"Analysis run {str(analysis_run.id)[:8]} staged with {len(selected_plugins)} plugin(s) (Pending execution)."
            )
            self.load_analysis_history(self.selected_evidence)
            self.select_analysis_run(analysis_run.id)

    def _poll_running_analysis_status(self) -> None:
        """Periodically refresh plugin runs and analysis history while worker is running."""
        if self.current_running_analysis_id is not None:
            self.load_plugin_runs_for_analysis(self.current_running_analysis_id)
            if self.selected_evidence is not None:
                runs = self.analysis_run_repository.list_by_evidence(
                    self.selected_evidence.id
                )
                self.populate_runs_table(runs)
                self.select_analysis_run(self.current_running_analysis_id)

    def _stop_status_poll_timer(self) -> None:
        """Stop status polling timer if active."""
        if self.status_poll_timer.isActive():
            self.status_poll_timer.stop()
        self.current_running_analysis_id = None

    def _on_analysis_finished(self, analysis_run: AnalysisRun) -> None:
        """Handle successful AnalysisWorker completion on the GUI thread."""
        self._stop_status_poll_timer()
        self._set_controls_enabled(True)
        if self.selected_evidence is not None:
            self.load_analysis_history(self.selected_evidence)
            self.select_analysis_run(analysis_run.id)

        status_str = analysis_run.status.value.upper()
        self.state_label.setText(
            f"Analysis run {str(analysis_run.id)[:8]} finished with status: {status_str}."
        )

        if self.analysis_worker is not None:
            self.analysis_worker.deleteLater()
            self.analysis_worker = None

    def _on_analysis_failed(self, error_message: str) -> None:
        """Handle unexpected AnalysisWorker failure on the GUI thread."""
        self._stop_status_poll_timer()
        self._set_controls_enabled(True)
        if self.selected_evidence is not None:
            self.load_analysis_history(self.selected_evidence)

        self.state_label.setText(f"Analysis execution error: {error_message}")

        if self.analysis_worker is not None:
            self.analysis_worker.deleteLater()
            self.analysis_worker = None

    def _set_controls_enabled(self, enabled: bool) -> None:
        """Enable or disable interactive UI controls during analysis execution."""
        self.run_button.setEnabled(enabled)
        self.select_all_btn.setEnabled(enabled)
        self.deselect_all_btn.setEnabled(enabled)
        self.evidence_combo.setEnabled(enabled)
        if not enabled:
            self.view_output_btn.setEnabled(False)
        else:
            self.on_plugin_run_selected()

    def load_analysis_history(self, evidence: Evidence) -> None:
        """Fetch and display past analysis runs for the selected evidence."""
        self.runs_table.setRowCount(0)
        self.plugin_runs_table.setRowCount(0)
        self.view_output_btn.setEnabled(False)

        try:
            runs = self.analysis_run_repository.list_by_evidence(evidence.id)
        except Exception as exc:
            self.state_label.setText(f"Unable to load analysis history: {exc}")
            return

        self.populate_runs_table(runs)

    def populate_runs_table(self, runs: list[AnalysisRun]) -> None:
        self.runs_table.setSortingEnabled(False)
        self.runs_table.setRowCount(len(runs))

        for row, run in enumerate(runs):
            created_str = run.created_at.astimezone().strftime("%Y-%m-%d %H:%M")
            status_str = run.status.value.upper()
            error_str = run.error_message if run.error_message else "None"

            values = [
                created_str,
                status_str,
                run.host_os.value.capitalize(),
                run.volatility_version,
                error_str,
            ]

            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, run)
                self.runs_table.setItem(row, col, item)

        self.runs_table.setSortingEnabled(True)

        if runs and self.runs_table.rowCount() > 0:
            self.runs_table.selectRow(0)

    def on_analysis_run_selected(self) -> None:
        """Update plugin execution status table when an AnalysisRun row is selected."""
        row = self.runs_table.currentRow()
        if row < 0:
            self.plugin_runs_table.setRowCount(0)
            self.view_output_btn.setEnabled(False)
            return

        item = self.runs_table.item(row, 0)
        if item is None:
            self.plugin_runs_table.setRowCount(0)
            self.view_output_btn.setEnabled(False)
            return

        run = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(run, AnalysisRun):
            self.plugin_runs_table.setRowCount(0)
            self.view_output_btn.setEnabled(False)
            return

        self.load_plugin_runs_for_analysis(run.id)

    def load_plugin_runs_for_analysis(self, analysis_run_id: UUID) -> None:
        """Fetch and display individual plugin run statuses."""
        try:
            plugin_runs = self.plugin_run_repository.list_by_analysis_run(
                analysis_run_id
            )
        except Exception as exc:
            self.state_label.setText(f"Unable to load plugin run statuses: {exc}")
            self.plugin_runs_table.setRowCount(0)
            self.view_output_btn.setEnabled(False)
            return

        self.plugin_runs_table.setRowCount(len(plugin_runs))

        for row, prun in enumerate(plugin_runs):
            started_str = (
                prun.started_at.astimezone().strftime("%H:%M:%S")
                if prun.started_at is not None
                else "N/A"
            )
            completed_or_err = (
                prun.error_message
                if prun.error_message
                else (
                    prun.completed_at.astimezone().strftime("%H:%M:%S")
                    if prun.completed_at is not None
                    else "N/A"
                )
            )

            values = [
                prun.plugin_name,
                prun.status.value.upper(),
                started_str,
                completed_or_err,
            ]

            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, prun)
                self.plugin_runs_table.setItem(row, col, item)

        if plugin_runs and self.plugin_runs_table.rowCount() > 0:
            self.plugin_runs_table.selectRow(0)
        else:
            self.on_plugin_run_selected()

    def on_plugin_run_selected(self) -> None:
        """Update View Output button state based on selected plugin run."""
        prun = self.get_selected_plugin_run()
        if prun is not None and prun.raw_output_path is not None:
            self.view_output_btn.setEnabled(True)
        else:
            self.view_output_btn.setEnabled(False)

    def get_selected_plugin_run(self) -> PluginRun | None:
        """Return the currently selected PluginRun from plugin_runs_table, if any."""
        row = self.plugin_runs_table.currentRow()
        if row < 0:
            return None
        item = self.plugin_runs_table.item(row, 0)
        if item is None:
            return None
        data = item.data(Qt.ItemDataRole.UserRole)
        return data if isinstance(data, PluginRun) else None

    def open_selected_plugin_output(self) -> None:
        """Open the generated output JSON file using the OS default application."""
        prun = self.get_selected_plugin_run()
        if prun is None:
            self.state_label.setText("No plugin run selected.")
            return

        if prun.raw_output_path is None:
            self.state_label.setText(
                f"No output file recorded for plugin run '{prun.plugin_name}'."
            )
            return

        out_path = Path(prun.raw_output_path)
        if not out_path.exists() or not out_path.is_file():
            self.state_label.setText(
                f"Output file for '{prun.plugin_name}' not found: {out_path}"
            )
            return

        url = QUrl.fromLocalFile(str(out_path.resolve()))
        success = QDesktopServices.openUrl(url)
        if success:
            self.state_label.setText(
                f"Opened output file for '{prun.plugin_name}': {out_path.name}"
            )
        else:
            self.state_label.setText(
                f"Could not open output file with system viewer: {out_path}"
            )

    def select_analysis_run(self, analysis_run_id: UUID) -> None:
        """Select row matching analysis_run_id in runs_table."""
        for row in range(self.runs_table.rowCount()):
            item = self.runs_table.item(row, 0)
            if item is None:
                continue
            run = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(run, AnalysisRun) and run.id == analysis_run_id:
                self.runs_table.selectRow(row)
                return

    def clear_all_views(self) -> None:
        """Reset all tables, lists, and summary cards."""
        self.evidence_info_card.setText("No evidence selected")
        self.plugins_status_label.setText(
            "Select an evidence item to configure plugins."
        )
        self.plugins_list.clear()
        self.runs_table.setRowCount(0)
        self.plugin_runs_table.setRowCount(0)
        self.run_button.setEnabled(False)
        self.select_all_btn.setEnabled(False)
        self.deselect_all_btn.setEnabled(False)
        self.view_output_btn.setEnabled(False)
