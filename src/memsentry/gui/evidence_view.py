"""Display and manage forensic RAM evidence registered for an active investigation case."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
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

from memsentry.gui.add_evidence_dialog import AddEvidenceDialog
from memsentry.models.case import Case
from memsentry.models.evidence import Evidence
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.volatility.plugin_applicability import (
    PluginApplicabilityService,
    PluginMetadata,
)


class EvidenceView(QWidget):
    """View widget listing evidence for the active case and showing plugin applicability."""

    evidence_created = Signal(object)

    def __init__(
        self,
        evidence_repository: EvidenceRepository,
        plugin_applicability_service: type[
            PluginApplicabilityService
        ] = PluginApplicabilityService,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.evidence_repository = evidence_repository
        self.plugin_applicability_service = plugin_applicability_service
        self.active_case: Case | None = None

        self._build_ui()
        self.update_case_state()

    def _build_ui(self) -> None:
        # Title and Header
        self.title_label = QLabel("Registered Evidence")
        self.title_label.setObjectName("pageTitle")
        self.subtitle_label = QLabel(
            "Manage RAM evidence files and view applicable forensic plugins."
        )

        self.state_label = QLabel()
        self.state_label.setObjectName("stateLabel")

        # Action Bar
        self.add_button = QPushButton("Add evidence")
        self.add_button.setEnabled(False)
        self.add_button.clicked.connect(self.open_add_evidence_dialog)

        actions_layout = QHBoxLayout()
        actions_layout.addStretch()
        actions_layout.addWidget(self.add_button)

        # Main Splitter (Left: Table, Right: Details Panel)
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left Panel: Evidence Table
        table_container = QWidget()
        table_layout = QVBoxLayout(table_container)
        table_layout.setContentsMargins(0, 0, 0, 0)

        self.evidence_table = QTableWidget(0, 6)
        self.evidence_table.setHorizontalHeaderLabels(
            ["Filename", "OS", "Size", "SHA-256", "Integrity", "Registered"]
        )
        self.evidence_table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.evidence_table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.evidence_table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )
        self.evidence_table.setSortingEnabled(True)
        self.evidence_table.itemSelectionChanged.connect(self.on_evidence_selected)
        self.evidence_table.horizontalHeader().setStretchLastSection(True)

        table_layout.addWidget(self.evidence_table)
        splitter.addWidget(table_container)

        # Right Panel: Details and Plugin Applicability
        details_container = QWidget()
        details_layout = QVBoxLayout(details_container)
        details_layout.setContentsMargins(0, 0, 0, 0)

        # Evidence Detail Card
        details_group = QGroupBox("Evidence Metadata")
        details_form = QVBoxLayout(details_group)

        self.detail_name_label = QLabel("Select an evidence file to view details")
        self.detail_path_label = QLabel("")
        self.detail_path_label.setWordWrap(True)
        self.detail_size_label = QLabel("")
        self.detail_sha256_label = QLabel("")
        self.detail_sha256_label.setWordWrap(True)
        self.detail_os_label = QLabel("")
        self.detail_integrity_label = QLabel("")
        self.detail_registered_label = QLabel("")

        details_form.addWidget(self.detail_name_label)
        details_form.addWidget(self.detail_path_label)
        details_form.addWidget(self.detail_size_label)
        details_form.addWidget(self.detail_sha256_label)
        details_form.addWidget(self.detail_os_label)
        details_form.addWidget(self.detail_integrity_label)
        details_form.addWidget(self.detail_registered_label)

        # Applicable Plugins Group
        self.plugins_group = QGroupBox("Applicable Volatility Plugins")
        plugins_layout = QVBoxLayout(self.plugins_group)

        self.plugins_status_label = QLabel(
            "Select an evidence item to view OS-applicable plugins."
        )
        self.plugins_list = QListWidget()

        plugins_layout.addWidget(self.plugins_status_label)
        plugins_layout.addWidget(self.plugins_list)

        details_layout.addWidget(details_group)
        details_layout.addWidget(self.plugins_group)
        splitter.addWidget(details_container)

        # Set Splitter ratio (60% table, 40% details)
        splitter.setSizes([600, 400])

        # Main Page Layout
        layout = QVBoxLayout(self)
        layout.addWidget(self.title_label)
        layout.addWidget(self.subtitle_label)
        layout.addLayout(actions_layout)
        layout.addWidget(self.state_label)
        layout.addWidget(splitter)

    def set_active_case(self, case: Case | None) -> None:
        """Set the active investigation case context and load its evidence."""
        self.active_case = case
        self.update_case_state()

    def update_case_state(self) -> None:
        """Update view UI depending on whether an active case is set."""
        if self.active_case is None:
            self.add_button.setEnabled(False)
            self.state_label.setText(
                "No case opened. Select or open a case to view registered evidence."
            )
            self.evidence_table.setRowCount(0)
            self.clear_details()
            return

        self.add_button.setEnabled(True)
        self.load_evidence()

    def load_evidence(self) -> None:
        """Load evidence records for the active case from EvidenceRepository."""
        if self.active_case is None:
            return

        self.state_label.setText("Loading evidence...")
        self.evidence_table.setRowCount(0)
        self.clear_details()

        try:
            records = self.evidence_repository.list_by_case(self.active_case.id)
        except Exception as exc:
            self.state_label.setText(f"Unable to load evidence: {exc}")
            return

        self.populate_evidence(records)

    def populate_evidence(self, records: list[Evidence]) -> None:
        """Populate table widget with evidence records."""
        self.evidence_table.setSortingEnabled(False)
        self.evidence_table.setRowCount(len(records))

        for row, evidence in enumerate(records):
            os_display = (
                evidence.evidence_os.value.capitalize()
                if evidence.evidence_os is not None
                else "Unknown"
            )
            size_display = f"{evidence.file_size_bytes:,} B"
            registered_str = evidence.registered_at.astimezone().strftime(
                "%Y-%m-%d %H:%M"
            )

            values = [
                evidence.original_filename,
                os_display,
                size_display,
                evidence.sha256[:16] + "...",
                evidence.integrity_status.value.capitalize(),
                registered_str,
            ]

            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, evidence)
                self.evidence_table.setItem(row, col, item)

        self.evidence_table.setSortingEnabled(True)

        if not records:
            self.state_label.setText(
                "No forensic evidence registered for this case yet. Click 'Add evidence' to begin."
            )
        else:
            self.state_label.setText(f"{len(records)} evidence file(s) registered")

    def on_evidence_selected(self) -> None:
        """Update detail panel and applicable plugins when table row is selected."""
        row = self.evidence_table.currentRow()
        if row < 0:
            self.clear_details()
            return

        item = self.evidence_table.item(row, 0)
        if item is None:
            self.clear_details()
            return

        evidence = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(evidence, Evidence):
            self.clear_details()
            return

        self.display_evidence_details(evidence)

    def display_evidence_details(self, evidence: Evidence) -> None:
        """Display details of the selected evidence record."""
        os_str = (
            evidence.evidence_os.value.capitalize()
            if evidence.evidence_os is not None
            else "Unknown"
        )
        reg_str = evidence.registered_at.astimezone().strftime("%Y-%m-%d %H:%M:%S UTC")

        self.detail_name_label.setText(f"<b>Filename:</b> {evidence.original_filename}")
        self.detail_path_label.setText(f"<b>Path:</b> {evidence.file_path}")
        self.detail_size_label.setText(
            f"<b>File Size:</b> {evidence.file_size_bytes:,} bytes"
        )
        self.detail_sha256_label.setText(f"<b>SHA-256:</b> {evidence.sha256}")
        self.detail_os_label.setText(f"<b>Target OS:</b> {os_str}")
        self.detail_integrity_label.setText(
            f"<b>Integrity Status:</b> {evidence.integrity_status.value.capitalize()}"
        )
        self.detail_registered_label.setText(f"<b>Registered At:</b> {reg_str}")

        self.update_plugin_applicability(evidence)

    def update_plugin_applicability(self, evidence: Evidence) -> None:
        """Query PluginApplicabilityService and populate the applicable plugins list."""
        self.plugins_list.clear()

        if evidence.evidence_os is None:
            self.plugins_status_label.setText(
                "Target OS is unknown. Select or set target OS to preview applicable plugins."
            )
            return

        plugins: list[PluginMetadata] = (
            self.plugin_applicability_service.get_available_plugins(
                evidence.evidence_os
            )
        )

        if not plugins:
            self.plugins_status_label.setText(
                f"No applicable core plugins for {evidence.evidence_os.value.capitalize()}."
            )
            return

        self.plugins_status_label.setText(
            f"{len(plugins)} applicable plugin(s) for {evidence.evidence_os.value.capitalize()}:"
        )

        for plugin in plugins:
            item_text = f"{plugin.name} — {plugin.description}"
            list_item = QListWidgetItem(item_text)
            list_item.setToolTip(
                f"Plugin: {plugin.name}\nCategory: {plugin.category.value}\n{plugin.description}"
            )
            self.plugins_list.addItem(list_item)

    def clear_details(self) -> None:
        """Reset details panel and plugins list to initial state."""
        self.detail_name_label.setText("Select an evidence file to view details")
        self.detail_path_label.clear()
        self.detail_size_label.clear()
        self.detail_sha256_label.clear()
        self.detail_os_label.clear()
        self.detail_integrity_label.clear()
        self.detail_registered_label.clear()

        self.plugins_status_label.setText(
            "Select an evidence item to view OS-applicable plugins."
        )
        self.plugins_list.clear()

    def open_add_evidence_dialog(self) -> None:
        """Open the AddEvidenceDialog for the active case."""
        if self.active_case is None:
            return

        dialog = AddEvidenceDialog(self.active_case.id, self.evidence_repository, self)
        dialog.evidence_created.connect(self.handle_evidence_created)
        dialog.exec()

    def handle_evidence_created(self, evidence: Evidence) -> None:
        """Refresh evidence list and select the newly registered evidence."""
        self.load_evidence()
        self.select_evidence(evidence)
        self.evidence_created.emit(evidence)

    def select_evidence(self, evidence: Evidence) -> None:
        """Select a specific evidence row in the table by Evidence.id."""
        for row in range(self.evidence_table.rowCount()):
            item = self.evidence_table.item(row, 0)
            if item is None:
                continue
            row_evidence = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(row_evidence, Evidence) and row_evidence.id == evidence.id:
                self.evidence_table.selectRow(row)
                return
