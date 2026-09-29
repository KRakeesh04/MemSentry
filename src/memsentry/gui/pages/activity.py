"""Inspect stage history, hash checks, plugin status, and audit actions."""

import logging
from typing import Any

from PySide6.QtCore import QEvent, QObject, QPoint, Qt
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
from memsentry.models.case import Case
from memsentry.storage.database import Database
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.workflow_repository import WorkflowRepository

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
    """QTableWidgetItem supporting custom sorting keys (e.g. numeric progress)."""

    def __init__(self, text: str, sort_key: str | int | float | None = None) -> None:
        super().__init__(text)
        self.sort_key = sort_key

    def __lt__(self, other: QTableWidgetItem) -> bool:
        if isinstance(other, SortableTableItem) and self.sort_key is not None and other.sort_key is not None:
            if isinstance(self.sort_key, str) and isinstance(other.sort_key, str):
                return self.sort_key < other.sort_key
            if isinstance(self.sort_key, (int, float)) and isinstance(other.sort_key, (int, float)):
                return self.sort_key < other.sort_key
        return super().__lt__(other)


class ActivityPage(QScrollArea):
    """Activity page displaying workflow events and integrity verification checkpoints."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.case: Case | None = None
        self.workspace_path = ""
        self.database: Database | None = None
        self.all_events: list[dict[str, Any]] = []
        self.filtered_events: list[dict[str, Any]] = []

        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        self._build_ui()

    def _build_ui(self) -> None:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(20)

        layout.addWidget(label("WORKFLOW & AUDIT LOG", "muted"))
        self.title = label("Activity", "pageTitle")
        layout.addWidget(self.title)
        self.subtitle = label(
            "Inspect stage history, hash integrity checks, plugin runs, and investigator actions.",
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

        # First row: dropdown filters
        filter_row = QHBoxLayout()

        self.evidence_combo = ThemedComboBox()
        self.evidence_combo.addItem("All evidence", None)
        self.evidence_combo.setToolTip("Filter by evidence item")
        self.evidence_combo.setEnabled(False)
        self.evidence_combo.currentIndexChanged.connect(
            self._evidence_changed
        )
        filter_row.addWidget(self.evidence_combo)


        self.run_combo = ThemedComboBox()
        self.run_combo.addItem("All runs", None)
        self.run_combo.setToolTip("Filter by analysis run")
        self.run_combo.setEnabled(False)
        self.run_combo.currentIndexChanged.connect(
            self._filter_events
        )
        filter_row.addWidget(self.run_combo)


        self.status_combo = ThemedComboBox()
        self.status_combo.addItems(
            ["All statuses", "Completed", "Running", "Failed"]
        )
        self.status_combo.currentIndexChanged.connect(
            self._filter_events
        )
        filter_row.addWidget(self.status_combo)


        self.integrity_combo = ThemedComboBox()
        self.integrity_combo.addItems(
            ["All integrity", "Verified Match", "Mismatch", "No Check"]
        )
        self.integrity_combo.currentIndexChanged.connect(
            self._filter_events
        )
        filter_row.addWidget(self.integrity_combo)


        filters_container.addLayout(filter_row)


        # Second row: search + refresh
        action_row = QHBoxLayout()

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText(
            "Search stage, phase, message, or hash"
        )
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(
            self._filter_events
        )

        action_row.addWidget(self.search_input, 1)


        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)

        action_row.addWidget(refresh_btn)


        filters_container.addLayout(action_row)

        layout.addLayout(filters_container)

    def _build_kpis(self, layout: QVBoxLayout) -> None:
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(16)

        self.total_card, self.total_val = _create_kpi_card("Total Events")
        kpi_row.addWidget(self.total_card, 1)

        self.integrity_card, self.integrity_val = _create_kpi_card("Integrity Checks")
        kpi_row.addWidget(self.integrity_card, 1)

        self.failures_card, self.failures_val = _create_kpi_card("Failures")
        kpi_row.addWidget(self.failures_card, 1)

        layout.addLayout(kpi_row)

    def _build_table(self, layout: QVBoxLayout) -> None:
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels([
            "Timestamp (UTC)",
            "Stage",
            "Phase",
            "Status",
            "Progress",
            "Integrity",
            "Message",
        ])

        header = self.table.horizontalHeader()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)

        self.table.setColumnWidth(0, 210)
        self.table.setColumnWidth(1, 95)
        self.table.setColumnWidth(2, 105)
        self.table.setColumnWidth(3, 120)
        self.table.setColumnWidth(4, 80)
        self.table.setColumnWidth(5, 90)

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
            "Open a case workspace\nto inspect its activity.",
            self.table.viewport(),
        )
        self.empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_state.setObjectName("tableEmptyState")
        self.empty_state.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents, True)
        self.empty_state.setWordWrap(True)
        self.table.viewport().installEventFilter(self)
        self.empty_state.setGeometry(self.table.viewport().rect())
        self.empty_state.show()

    def eventFilter(self, obj: QObject, event: QEvent) -> bool:
        if obj is self.table.viewport() and event.type() == QEvent.Type.Resize:
            self.empty_state.setGeometry(self.table.viewport().rect())
        return super().eventFilter(obj, event)

    def open_case(self, workspace_path: str, case: Case | None) -> None:
        """Set active workspace and case, then load activity events."""
        self.workspace_path = workspace_path
        self.case = case

        if workspace_path:
            self.database = workspace_database(workspace_path)
        else:
            self.database = None

        has_case = self.database is not None and case is not None
        self.evidence_combo.setEnabled(has_case)
        self.run_combo.setEnabled(has_case)

        self.title.setText(f"Activity · {case.case_number if case else ''}")
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
                    self.run_combo.addItem(f"Run {str(run.id)[:8]} ({run.status})", run)
            except Exception:
                logger.exception("Failed to populate runs for evidence")

        self.run_combo.blockSignals(False)
        self._filter_events()

    def refresh(self) -> None:
        """Fetch workflow events from database and re-render layout."""
        if not self.database:
            self.all_events = []
            self.filtered_events = []
            self._render_events([])
            self.empty_state.setText("Open a case workspace\nto inspect its activity.")
            self.empty_state.show()
            self.empty_state.raise_()
            self.message.setText("")
            return

        try:
            repo = WorkflowRepository(self.database)
            self.all_events = repo.list_events()
            self.message.setText("")
        except Exception as exc:
            logger.exception("Could not read workflow events from database")
            self.all_events = []
            self.filtered_events = []
            self.message.setText(f"Could not read workflow events: {exc}")

        self._filter_events()

    def _filter_events(self, *args: object) -> None:
        query = self.search_input.text().strip().lower()
        status_filter = self.status_combo.currentText().lower()
        integrity_filter = self.integrity_combo.currentText().lower()
        selected_evidence = self.evidence_combo.currentData()
        selected_run = self.run_combo.currentData()

        filtered = []
        for event in self.all_events:
            # Filter by selected evidence
            if selected_evidence and str(event.get("evidence_id", "")) != str(selected_evidence.id):
                continue

            # Filter by selected run
            if selected_run and str(event.get("analysis_run_id", "")) != str(selected_run.id):
                continue

            # Filter by status
            st_norm = str(event.get("status", "")).strip().lower()
            if status_filter != "all statuses" and st_norm != status_filter:
                continue

            # Filter by integrity
            expected = event.get("expected_sha256")
            actual = event.get("actual_sha256")
            has_check = bool(expected and actual)
            is_match = has_check and (expected == actual)

            if integrity_filter == "verified match" and not (has_check and is_match):
                continue
            if integrity_filter == "mismatch" and not (has_check and not is_match):
                continue
            if integrity_filter == "no check" and has_check:
                continue

            # Search query
            if query:
                searchable = " ".join([
                    str(event.get("stage", "")),
                    str(event.get("phase", "")),
                    str(event.get("status", "")),
                    str(event.get("expected_sha256", "") or ""),
                    str(event.get("actual_sha256", "") or ""),
                    str(event.get("message", "")),
                ]).lower()
                if query not in searchable:
                    continue

            filtered.append(event)

        self.filtered_events = filtered
        self._render_events(filtered)

    def _format_timestamp(self, iso_string: str) -> str:
        if not iso_string:
            return "—"
        s = str(iso_string).replace("T", " ")
        if len(s) >= 19:
            return s[:19] + " UTC"
        return s

    def _render_events(self, events: list[dict[str, Any]]) -> None:
        sorting_was_enabled = self.table.isSortingEnabled()
        self.table.setSortingEnabled(False)
        self.table.setRowCount(0)

        # Repository returns oldest first; Activity page defaults to newest first.
        display_events = list(reversed(events))
        self.table.setRowCount(len(display_events))

        for row, event in enumerate(display_events):
            created_at = str(event.get("created_at", ""))
            stage = str(event.get("stage", ""))
            phase = str(event.get("phase", ""))
            status = str(event.get("status", "")).capitalize()
            progress = event.get("progress", 0)

            expected = event.get("expected_sha256")
            actual = event.get("actual_sha256")
            msg = str(event.get("message", ""))

            if expected and actual:
                sha256_integrity = "✓ Match" if expected == actual else "✗ Mismatch"
            else:
                sha256_integrity = "—"

            timestamp_display = self._format_timestamp(created_at)

            t_item = SortableTableItem(timestamp_display, sort_key=created_at)
            s_item = SortableTableItem(stage, sort_key=stage)
            p_item = SortableTableItem(phase, sort_key=phase)

            status_icon = "✓ " if status.lower() == "completed" else ("❌ " if status.lower() == "failed" else "⏳ ")
            st_item = SortableTableItem(f"{status_icon}{status}", sort_key=status)

            pr_item = SortableTableItem(f"{progress}%", sort_key=progress)
            integrity_item = SortableTableItem(sha256_integrity, sort_key=sha256_integrity)
            msg_item = SortableTableItem(msg, sort_key=msg)

            t_item.setToolTip(created_at)
            msg_item.setToolTip(msg)

            if expected or actual:
                integrity_item.setToolTip(
                    f"Expected SHA-256:\n{expected or 'N/A'}\n\n"
                    f"Actual SHA-256:\n{actual or 'N/A'}"
                )

            st_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            pr_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            integrity_item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

            t_item.setData(Qt.ItemDataRole.UserRole, event)

            self.table.setItem(row, 0, t_item)
            self.table.setItem(row, 1, s_item)
            self.table.setItem(row, 2, p_item)
            self.table.setItem(row, 3, st_item)
            self.table.setItem(row, 4, pr_item)
            self.table.setItem(row, 5, integrity_item)
            self.table.setItem(row, 6, msg_item)

        self.table.setSortingEnabled(sorting_was_enabled)
        self._update_empty_state_and_kpis(events)

    def _update_empty_state_and_kpis(self, events: list[dict[str, Any]]) -> None:
        total_loaded = len(self.all_events)
        filtered_count = len(events)

        total_checks = 0
        passed_hash_checks = 0
        mismatch_count = 0
        failed_count = 0

        for event in events:
            st = str(event.get("status", "")).strip().lower()
            expected = event.get("expected_sha256")
            actual = event.get("actual_sha256")

            if expected and actual:
                total_checks += 1
                if expected == actual:
                    if st == "completed":
                        passed_hash_checks += 1
                else:
                    mismatch_count += 1

            if st == "failed":
                failed_count += 1

        if events:
            self.empty_state.hide()
        elif self.database:
            if total_loaded == 0:
                self.empty_state.setText("No activity events recorded yet.")
            else:
                self.empty_state.setText("No activity events match\nthe current filters.")
            self.empty_state.show()
            self.empty_state.raise_()

        if total_loaded > 0 and filtered_count != total_loaded:
            self.total_val.setText(f"{filtered_count} of {total_loaded}")
        else:
            self.total_val.setText(str(filtered_count))

        if mismatch_count > 0:
            self.integrity_val.setText(f"{passed_hash_checks} / {total_checks} ({mismatch_count} Mismatch)")
        elif total_checks > 0:
            self.integrity_val.setText(f"{passed_hash_checks} / {total_checks} Verified")
        else:
            self.integrity_val.setText("0 Verified")

        self.failures_val.setText(f"{failed_count} Failed")

    def _show_details(self, row: int, col: int) -> None:
        item = self.table.item(row, 0)
        if not item:
            return
        event = item.data(Qt.ItemDataRole.UserRole)
        if not event:
            return

        dialog = QMessageBox(self)
        dialog.setWindowTitle("Activity Event Details")
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText(
            f"Stage: {event.get('stage')} | Phase: {event.get('phase')} | Status: {event.get('status')}"
        )
        detail_text = (
            f"Event ID: {event.get('id')}\n"
            f"Timestamp (UTC): {event.get('created_at')}\n"
            f"Evidence ID: {event.get('evidence_id')}\n"
            f"Analysis Run ID: {event.get('analysis_run_id') or 'N/A'}\n"
            f"Progress: {event.get('progress')}%\n"
            f"Expected SHA-256: {event.get('expected_sha256') or 'N/A'}\n"
            f"Actual SHA-256:   {event.get('actual_sha256') or 'N/A'}\n\n"
            f"Message:\n{event.get('message') or 'No detailed message.'}"
        )
        dialog.setDetailedText(detail_text)
        dialog.exec()

    def _show_context_menu(self, pos: QPoint) -> None:
        item = self.table.itemAt(pos)
        if not item:
            return
        row = item.row()
        first_item = self.table.item(row, 0)
        if not first_item:
            return
        event = first_item.data(Qt.ItemDataRole.UserRole)
        if not event:
            return

        menu = QMenu(self)
        view_action = menu.addAction("View Event Details")
        menu.addSeparator()

        copy_msg = menu.addAction("Copy Message")
        copy_exp = menu.addAction("Copy Expected SHA-256") if event.get("expected_sha256") else None
        copy_act = menu.addAction("Copy Actual SHA-256") if event.get("actual_sha256") else None
        copy_id = menu.addAction("Copy Event ID")

        chosen = menu.exec(self.table.viewport().mapToGlobal(pos))
        clipboard = QApplication.clipboard()

        if chosen == view_action:
            self._show_details(row, 0)
        elif chosen == copy_msg:
            clipboard.setText(str(event.get("message", "")))
        elif copy_exp and chosen == copy_exp:
            clipboard.setText(str(event.get("expected_sha256", "")))
        elif copy_act and chosen == copy_act:
            clipboard.setText(str(event.get("actual_sha256", "")))
        elif chosen == copy_id:
            clipboard.setText(str(event.get("id", "")))


def create_page() -> ActivityPage:
    return ActivityPage()
