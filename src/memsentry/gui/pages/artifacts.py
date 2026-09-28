"""Artifacts page for searching and inspecting captured memory artifacts."""

import json
import logging

from PySide6.QtCore import QEvent, Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMenu,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from memsentry.app.case_service import workspace_database
from memsentry.gui.controls import ThemedComboBox
from memsentry.models.artifact import Artifact
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository

logger = logging.getLogger(__name__)


def label(text: str, style: str = "") -> QLabel:
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setWordWrap(True)
    if style:
        widget.setObjectName(style)
    widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return widget


def _create_kpi_card(title: str) -> tuple[QFrame, QLabel]:
    card = QFrame()
    card.setObjectName("card")
    card_layout = QVBoxLayout(card)
    card_layout.setContentsMargins(16, 12, 16, 12)
    card_layout.addWidget(label(title, "muted"))
    value_label = label("0", "sectionTitle")
    card_layout.addWidget(value_label)
    return card, value_label


class SortableTableItem(QTableWidgetItem):
    """QTableWidgetItem supporting custom sorting keys (e.g. numeric PID)."""

    def __init__(self, text: str, sort_key=None):
        super().__init__(text)
        self.sort_key = sort_key

    def __lt__(self, other):
        if isinstance(other, SortableTableItem) and self.sort_key is not None and other.sort_key is not None:
            return self.sort_key < other.sort_key
        return super().__lt__(other)


def _extract_artifact_summary(artifact: Artifact) -> tuple[str, str, str]:
    """Extract display name, details summary, and provenance source from artifact data."""
    data = artifact.original_data
    if isinstance(data, dict) and "normalized" in data and isinstance(data["normalized"], dict):
        norm = data["normalized"]
    elif isinstance(data, dict):
        norm = data
    else:
        norm = {}

    name = (
        norm.get("process_name")
        or norm.get("ImageFileName")
        or norm.get("name")
        or norm.get("rule")
        or norm.get("rule_name")
        or norm.get("filename")
        or norm.get("os_name")
        or (f"PID {artifact.pid}" if artifact.pid is not None else "—")
    )

    # Details string
    if "cmdline" in norm and norm["cmdline"]:
        details = str(norm["cmdline"])
    elif "command" in norm and norm["command"]:
        details = str(norm["command"])
    elif "CommandLine" in norm and norm["CommandLine"]:
        details = str(norm["CommandLine"])
    elif "local_address" in norm or "foreign_address" in norm:
        l_addr = norm.get("local_address", "")
        l_port = norm.get("local_port", "")
        f_addr = norm.get("foreign_address", "")
        f_port = norm.get("foreign_port", "")
        state = norm.get("state", "")
        details = f"{l_addr}:{l_port} -> {f_addr}:{f_port} ({state})".strip()
    elif "hostname" in norm or "architecture" in norm:
        details = f"Host: {norm.get('hostname', 'N/A')} | Arch: {norm.get('architecture', 'N/A')} | Ver: {norm.get('os_version', 'N/A')}"
    elif "match" in norm or "string" in norm:
        details = f"Rule: {norm.get('rule', 'N/A')} | Match: {norm.get('match', norm.get('string', ''))}"
    else:
        # Generic key-value summary
        summary_items = [f"{k}: {v}" for k, v in norm.items() if k not in ("process_name", "name", "pid")][:3]
        details = " | ".join(summary_items) if summary_items else json.dumps(norm)[:80]

    prov_source = artifact.provenance.get("source") or artifact.provenance.get("plugin") or "Volatility 3"
    return str(name), str(details), str(prov_source)


class ArtifactsPage(QScrollArea):
    """Artifacts page for searching and inspecting captured memory artifacts."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        self.workspace_path = ""
        self.database = None
        self.all_artifacts: list[Artifact] = []
        self.filtered_artifacts: list[Artifact] = []

        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        self._build_ui()

    def _build_ui(self) -> None:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(20)

        layout.addWidget(label("MEMORY ARTIFACT EXPLORER", "muted"))
        self.title = label("Artifacts", "pageTitle")
        layout.addWidget(self.title)
        self.subtitle = label(
            "Search processes, command lines, network sockets, handles, DLLs, and YARA matches captured in memory.",
            "muted",
        )
        layout.addWidget(self.subtitle)

        # Filters
        self._build_filters(layout)

        # KPI Summary Cards
        self._build_kpis(layout)

        # Table
        self._build_table(layout)

        self.message = label("")
        layout.addWidget(self.message)

        self.setWidget(content)

    def _build_filters(self, layout: QVBoxLayout) -> None:
        filters_container = QVBoxLayout()

        filter_row = QHBoxLayout()

        self.evidence_combo = ThemedComboBox()
        self.evidence_combo.addItem("All evidence", None)
        self.evidence_combo.setToolTip("Filter by evidence item")
        self.evidence_combo.setEnabled(False)
        self.evidence_combo.currentIndexChanged.connect(self._evidence_changed)
        filter_row.addWidget(self.evidence_combo)

        self.run_combo = ThemedComboBox()
        self.run_combo.addItem("All runs", None)
        self.run_combo.setToolTip("Filter by analysis run")
        self.run_combo.setEnabled(False)
        self.run_combo.currentIndexChanged.connect(self._filter_artifacts)
        filter_row.addWidget(self.run_combo)

        self.type_combo = ThemedComboBox()
        self.type_combo.addItem("All types", None)
        self.type_combo.setToolTip("Filter by artifact type")
        self.type_combo.currentIndexChanged.connect(self._filter_artifacts)
        filter_row.addWidget(self.type_combo)

        filters_container.addLayout(filter_row)

        action_row = QHBoxLayout()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search PID, process name, command, IP/port, or details...")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._filter_artifacts)
        action_row.addWidget(self.search_input, 1)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        action_row.addWidget(refresh_btn)

        filters_container.addLayout(action_row)

        layout.addLayout(filters_container)

    def _build_kpis(self, layout: QVBoxLayout) -> None:
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(16)

        self.total_card, self.total_val = _create_kpi_card("Total Artifacts")
        kpi_row.addWidget(self.total_card, 1)

        self.pids_card, self.pids_val = _create_kpi_card("Unique PIDs")
        kpi_row.addWidget(self.pids_card, 1)

        self.types_card, self.types_val = _create_kpi_card("Artifact Types")
        kpi_row.addWidget(self.types_card, 1)

        layout.addLayout(kpi_row)

    def _build_table(self, layout: QVBoxLayout) -> None:
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels([
            "PID",
            "Type",
            "Name / Key",
            "Details / Command",
            "Plugin Source",
            "Captured (UTC)",
        ])

        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)

        self.table.setColumnWidth(0, 80)
        self.table.setColumnWidth(1, 110)
        self.table.setColumnWidth(2, 160)
        self.table.setColumnWidth(4, 160)
        self.table.setColumnWidth(5, 180)

        self.table.verticalHeader().hide()
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.table.setAlternatingRowColors(True)
        self.table.setMinimumHeight(350)
        self.table.setSortingEnabled(True)

        self.table.cellDoubleClicked.connect(self._show_details)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._show_context_menu)

        layout.addWidget(self.table)

        self.empty_state = QLabel(
            "Open a case workspace\nto inspect captured artifacts.",
            self.table.viewport(),
        )
        self.empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_state.setObjectName("tableEmptyState")
        self.empty_state.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.empty_state.setWordWrap(True)
        self.table.viewport().installEventFilter(self)
        self.empty_state.setGeometry(self.table.viewport().rect())
        self.empty_state.show()

    def eventFilter(self, obj, event):
        if obj is self.table.viewport() and event.type() == QEvent.Type.Resize:
            self.empty_state.setGeometry(self.table.viewport().rect())
        return super().eventFilter(obj, event)

    def open_case(self, workspace_path: str, case) -> None:
        """Set active workspace and case, then load artifacts."""
        self.workspace_path = workspace_path
        self.case = case

        if workspace_path:
            self.database = workspace_database(workspace_path)
        else:
            self.database = None

        has_case = self.database is not None and case is not None
        self.evidence_combo.setEnabled(has_case)
        self.run_combo.setEnabled(has_case)

        self.title.setText(f"Artifacts · {case.case_number if case else ''}")
        self._populate_evidence_and_runs()
        self.refresh()

    def _populate_evidence_and_runs(self) -> None:
        self.evidence_combo.blockSignals(True)
        self.run_combo.blockSignals(True)

        self.evidence_combo.clear()
        self.evidence_combo.addItem("All evidence", None)

        self.run_combo.clear()
        self.run_combo.addItem("All runs", None)

        if not self.database or not self.case:
            self.evidence_combo.blockSignals(False)
            self.run_combo.blockSignals(False)
            return

        try:
            evidences = EvidenceRepository(self.database).list_by_case(self.case.id)
            for ev in evidences:
                label_text = f"{ev.original_filename} ({ev.sha256[:8]}…)"
                self.evidence_combo.addItem(label_text, ev)
        except Exception:
            logger.exception("Failed to populate evidence items for case")

        self.evidence_combo.blockSignals(False)
        self.run_combo.blockSignals(False)

    def _evidence_changed(self) -> None:
        self.run_combo.blockSignals(True)
        self.run_combo.clear()
        self.run_combo.addItem("All runs", None)

        evidence = self.evidence_combo.currentData()
        if self.database and evidence:
            try:
                runs = AnalysisRunRepository(self.database).list_by_evidence(evidence.id)
                for run in runs:
                    self.run_combo.addItem(f"Run {run.id[:8]} ({run.status})", run)
            except Exception:
                logger.exception("Failed to populate runs for evidence")

        self.run_combo.blockSignals(False)
        self._filter_artifacts()

    def refresh(self) -> None:
        """Fetch artifacts from database and re-render layout."""
        if not self.database:
            self.all_artifacts = []
            self.filtered_artifacts = []
            self._render_artifacts([])
            self.empty_state.setText("Open a case workspace\nto inspect captured artifacts.")
            self.empty_state.show()
            self.empty_state.raise_()
            self.message.setText("")
            return

        try:
            repo = ArtifactRepository(self.database)
            self.all_artifacts = repo.list_all()
            self._update_type_combo()
            self.message.setText("")
        except Exception as exc:
            logger.exception("Could not read artifacts from database")
            self.all_artifacts = []
            self.filtered_artifacts = []
            self.message.setText(f"Could not read artifacts: {exc}")

        self._filter_artifacts()

    def _update_type_combo(self) -> None:
        self.type_combo.blockSignals(True)
        current_selection = self.type_combo.currentText()
        self.type_combo.clear()
        self.type_combo.addItem("All types", None)

        types = sorted({art.artifact_type for art in self.all_artifacts if art.artifact_type})
        for t in types:
            self.type_combo.addItem(t.capitalize(), t)

        index = self.type_combo.findText(current_selection)
        if index >= 0:
            self.type_combo.setCurrentIndex(index)
        self.type_combo.blockSignals(False)

    def _filter_artifacts(self, *args) -> None:
        query = self.search_input.text().strip().lower()
        selected_type = self.type_combo.currentData()
        selected_evidence = self.evidence_combo.currentData()
        selected_run = self.run_combo.currentData()

        # If specific run selected vs evidence selected
        valid_run_ids = None
        if selected_run:
            valid_run_ids = {str(selected_run.id)}
        elif selected_evidence and self.database:
            try:
                runs = AnalysisRunRepository(self.database).list_by_evidence(selected_evidence.id)
                valid_run_ids = {str(r.id) for r in runs}
            except Exception:
                valid_run_ids = None

        filtered = []
        for artifact in self.all_artifacts:
            # Filter by analysis run / evidence
            if valid_run_ids is not None and str(artifact.analysis_run_id) not in valid_run_ids:
                continue

            # Filter by artifact type
            if selected_type and artifact.artifact_type != selected_type:
                continue

            name, details, source = _extract_artifact_summary(artifact)

            # Search query
            if query:
                searchable = " ".join([
                    str(artifact.pid if artifact.pid is not None else ""),
                    str(artifact.artifact_type),
                    name,
                    details,
                    source,
                    json.dumps(artifact.original_data),
                ]).lower()
                if query not in searchable:
                    continue

            filtered.append(artifact)

        self.filtered_artifacts = filtered
        self._render_artifacts(filtered)

    def _format_timestamp(self, dt_val) -> str:
        if not dt_val:
            return "—"
        s = str(dt_val).replace("T", " ")
        if len(s) >= 19:
            return s[:19] + " UTC"
        return s

    def _render_artifacts(self, artifacts: list[Artifact]) -> None:
        sorting_was_enabled = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)

        display_artifacts = list(reversed(artifacts))
        self.table.setRowCount(len(display_artifacts))

        for row, artifact in enumerate(display_artifacts):
            pid_str = str(artifact.pid) if artifact.pid is not None else "—"
            pid_sort = artifact.pid if artifact.pid is not None else -1

            name, details, source = _extract_artifact_summary(artifact)
            created_str = self._format_timestamp(artifact.created_at)

            pid_item = SortableTableItem(pid_str, sort_key=pid_sort)
            type_item = SortableTableItem(artifact.artifact_type, sort_key=artifact.artifact_type)
            name_item = SortableTableItem(name, sort_key=name)
            details_item = SortableTableItem(details, sort_key=details)
            source_item = SortableTableItem(source, sort_key=source)
            created_item = SortableTableItem(created_str, sort_key=str(artifact.created_at))

            pid_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            type_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            details_item.setToolTip(details)
            created_item.setToolTip(str(artifact.created_at))

            pid_item.setData(Qt.ItemDataRole.UserRole, artifact)

            self.table.setItem(row, 0, pid_item)
            self.table.setItem(row, 1, type_item)
            self.table.setItem(row, 2, name_item)
            self.table.setItem(row, 3, details_item)
            self.table.setItem(row, 4, source_item)
            self.table.setItem(row, 5, created_item)

        self.table.setSortingEnabled(sorting_was_enabled)
        self._update_empty_state_and_kpis(artifacts)

    def _update_empty_state_and_kpis(self, artifacts: list[Artifact]) -> None:
        total_loaded = len(self.all_artifacts)
        filtered_count = len(artifacts)

        unique_pids = {art.pid for art in artifacts if art.pid is not None}
        unique_types = {art.artifact_type for art in artifacts if art.artifact_type}

        if artifacts:
            self.empty_state.hide()
        elif self.database:
            if total_loaded == 0:
                self.empty_state.setText("No memory artifacts recorded yet.")
            else:
                self.empty_state.setText("No artifacts match\nthe current filters.")
            self.empty_state.show()
            self.empty_state.raise_()

        if total_loaded > 0 and filtered_count != total_loaded:
            self.total_val.setText(f"{filtered_count} of {total_loaded}")
        else:
            self.total_val.setText(str(filtered_count))

        self.pids_val.setText(str(len(unique_pids)))
        self.types_val.setText(str(len(unique_types)))

    def _show_details(self, row: int, col: int) -> None:
        item = self.table.item(row, 0)
        if not item:
            return
        artifact = item.data(Qt.ItemDataRole.UserRole)
        if not artifact or not isinstance(artifact, Artifact):
            return

        name, details, source = _extract_artifact_summary(artifact)

        dialog = QMessageBox(self)
        dialog.setWindowTitle("Artifact Details")
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText(
            f"Type: {artifact.artifact_type} | PID: {artifact.pid if artifact.pid is not None else 'N/A'} | Source: {source}"
        )
        detail_text = (
            f"Artifact ID: {artifact.id}\n"
            f"Type: {artifact.artifact_type}\n"
            f"PID: {artifact.pid if artifact.pid is not None else 'N/A'}\n"
            f"Analysis Run ID: {artifact.analysis_run_id}\n"
            f"Plugin Run ID: {artifact.plugin_run_id}\n"
            f"Captured (UTC): {artifact.created_at}\n\n"
            f"Provenance Metadata:\n{json.dumps(artifact.provenance, indent=2)}\n\n"
            f"Original Data:\n{json.dumps(artifact.original_data, indent=2)}"
        )
        dialog.setDetailedText(detail_text)
        dialog.exec()

    def _show_context_menu(self, pos) -> None:
        item = self.table.itemAt(pos)
        if not item:
            return
        row = item.row()
        first_item = self.table.item(row, 0)
        if not first_item:
            return
        artifact = first_item.data(Qt.ItemDataRole.UserRole)
        if not artifact or not isinstance(artifact, Artifact):
            return

        name, details, source = _extract_artifact_summary(artifact)

        menu = QMenu(self)
        view_action = menu.addAction("View Artifact Details")
        menu.addSeparator()

        copy_name = menu.addAction("Copy Name / Value")
        copy_details = menu.addAction("Copy Details")
        copy_pid = menu.addAction("Copy PID") if artifact.pid is not None else None
        copy_id = menu.addAction("Copy Artifact ID")
        copy_json = menu.addAction("Copy Original JSON Data")

        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        clipboard = QApplication.clipboard()

        if chosen == view_action:
            self._show_details(row, 0)
        elif chosen == copy_name:
            clipboard.setText(name)
        elif chosen == copy_details:
            clipboard.setText(details)
        elif copy_pid and chosen == copy_pid:
            clipboard.setText(str(artifact.pid))
        elif chosen == copy_id:
            clipboard.setText(str(artifact.id))
        elif chosen == copy_json:
            clipboard.setText(json.dumps(artifact.original_data, indent=2))


def create_page():
    return ArtifactsPage()
