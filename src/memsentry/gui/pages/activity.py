"""Inspect stage history, hash checks, plugin status, and audit actions."""

from PySide6.QtCore import Qt, QEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
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
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.workflow_repository import WorkflowRepository


def label(text: str, style: str = "") -> QLabel:
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setWordWrap(True)
    if style:
        widget.setObjectName(style)
    widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return widget

class ActivityPage(QScrollArea):
    """Activity page displaying workflow events and integrity verification checkpoints."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        self.workspace_path = ""
        self.database = None
        self.all_events = []
        self.filtered_events = []

        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

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

        # Filters and search row
        filters_row = QHBoxLayout()

        self.evidence_combo = ThemedComboBox()
        self.evidence_combo.addItem("All evidence", None)
        self.evidence_combo.setToolTip("Filter by evidence item")
        self.evidence_combo.setEnabled(False)
        self.evidence_combo.currentIndexChanged.connect(self._evidence_changed)
        filters_row.addWidget(self.evidence_combo)

        self.run_combo = ThemedComboBox()
        self.run_combo.addItem("All runs", None)
        self.run_combo.setToolTip("Filter by analysis run")
        self.run_combo.setEnabled(False)
        self.run_combo.currentIndexChanged.connect(self._filter_events)
        filters_row.addWidget(self.run_combo)

        self.status_combo = ThemedComboBox()
        self.status_combo.addItems(["All statuses", "Completed", "Running", "Failed"])
        self.status_combo.currentIndexChanged.connect(self._filter_events)
        filters_row.addWidget(self.status_combo)

        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search stage, phase, message, or hash")
        self.search_input.setClearButtonEnabled(True)
        self.search_input.textChanged.connect(self._filter_events)
        filters_row.addWidget(self.search_input, 1)

        refresh_btn = QPushButton("Refresh")
        refresh_btn.clicked.connect(self.refresh)
        filters_row.addWidget(refresh_btn)

        layout.addLayout(filters_row)

        # KPI Summary cards
        kpi_row = QHBoxLayout()
        kpi_row.setSpacing(16)

        self.total_card = QFrame()
        self.total_card.setObjectName("card")
        total_layout = QVBoxLayout(self.total_card)
        total_layout.setContentsMargins(16, 12, 16, 12)
        total_layout.addWidget(label("Total Events", "muted"))
        self.total_val = label("0", "sectionTitle")
        total_layout.addWidget(self.total_val)
        kpi_row.addWidget(self.total_card, 1)

        self.integrity_card = QFrame()
        self.integrity_card.setObjectName("card")
        integrity_layout = QVBoxLayout(self.integrity_card)
        integrity_layout.setContentsMargins(16, 12, 16, 12)
        integrity_layout.addWidget(label("Integrity Checks", "muted"))
        self.integrity_val = label("0 Passed", "sectionTitle")
        integrity_layout.addWidget(self.integrity_val)
        kpi_row.addWidget(self.integrity_card, 1)

        self.failures_card = QFrame()
        self.failures_card.setObjectName("card")
        failures_layout = QVBoxLayout(self.failures_card)
        failures_layout.setContentsMargins(16, 12, 16, 12)
        failures_layout.addWidget(label("Failures", "muted"))
        self.failures_val = label("0 Failed", "sectionTitle")
        failures_layout.addWidget(self.failures_val)
        kpi_row.addWidget(self.failures_card, 1)

        layout.addLayout(kpi_row)

        # Table
        self.table = QTableWidget(0, 7)

        self.table.setHorizontalHeaderLabels([
            "Timestamp (UTC)",
            "Stage",
            "Phase",
            "Status",
            "Progress",
            "Integrity",
            "Message / Details",
        ])

        header = self.table.horizontalHeader()

        # Use predictable widths for the important columns.
        header.setStretchLastSection(False)

        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.Fixed)

        # Message column consumes all remaining space.
        header.setSectionResizeMode(6, QHeaderView.ResizeMode.Stretch)

        self.table.setColumnWidth(0, 175)  # Timestamp
        self.table.setColumnWidth(1, 95)   # Stage
        self.table.setColumnWidth(2, 105)  # Phase
        self.table.setColumnWidth(3, 100)  # Status
        self.table.setColumnWidth(4, 80)   # Progress
        self.table.setColumnWidth(5, 95)   # Integrity

        self.table.verticalHeader().hide()
        self.table.setShowGrid(False)

        self.table.setSelectionBehavior(
            QAbstractItemView.SelectionBehavior.SelectRows
        )
        self.table.setSelectionMode(
            QAbstractItemView.SelectionMode.SingleSelection
        )
        self.table.setEditTriggers(
            QAbstractItemView.EditTrigger.NoEditTriggers
        )

        self.table.setWordWrap(False)
        self.table.setTextElideMode(Qt.TextElideMode.ElideRight)
        self.table.setAlternatingRowColors(True)

        self.table.setMinimumHeight(350)

        self.table.cellDoubleClicked.connect(self._show_details)

        layout.addWidget(self.table)

        self.empty_state = QLabel(
            "Open a case workspace\nto inspect its activity.",
            self.table.viewport(),
        )

        self.empty_state.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_state.setObjectName("tableEmptyState")
        self.empty_state.setAttribute(
            Qt.WidgetAttribute.WA_TransparentForMouseEvents,
            True,
        )

        self.empty_state.setWordWrap(True)

        # Watch the table body for resizing so the message stays centered.
        self.table.viewport().installEventFilter(self)

        self.empty_state.setGeometry(self.table.viewport().rect())
        self.empty_state.show()

        self.message = label("")
        layout.addWidget(self.message)

        self.setWidget(content)

    def eventFilter(self, obj, event):
        if (
            obj is self.table.viewport()
            and event.type() == QEvent.Type.Resize
        ):
            self.empty_state.setGeometry(
                self.table.viewport().rect()
            )

        return super().eventFilter(obj, event)

    def open_case(self, workspace_path: str, case) -> None:
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
            pass

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
                pass

        self.run_combo.blockSignals(False)
        self._filter_events()

    def refresh(self) -> None:
        """Fetch workflow events from database and re-render layout."""
        if not self.database:
            self.all_events = []

            self._render_events([])

            self.empty_state.setText(
                "Open a case workspace\nto inspect its activity."
            )
            self.empty_state.show()
            self.empty_state.raise_()

            self.message.setText("")
            return

        evidence = self.evidence_combo.currentData()
        run = self.run_combo.currentData()

        try:
            repo = WorkflowRepository(self.database)
            self.all_events = repo.list_events(
                evidence_id=evidence.id if evidence else None,
                run_id=run.id if run else None,
            )
            self.message.setText("")
        except Exception as exc:
            self.all_events = []
            self.message.setText(f"Could not read workflow events: {exc}")

        self._filter_events()

    def _filter_events(self, *args) -> None:
        query = self.search_input.text().strip().lower()
        status_filter = self.status_combo.currentText().lower()

        filtered = []
        for event in self.all_events:
            if status_filter != "all statuses" and event.get("status", "").lower() != status_filter:
                continue

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

        self._render_events(filtered)

    def _render_events(self, events: list[dict]) -> None:
        self.table.setRowCount(0)

        # Repository returns oldest first; Activity shows newest first.
        display_events = list(reversed(events))
        self.table.setRowCount(len(display_events))

        total_count = len(events)
        passed_hash_checks = 0
        failed_count = 0

        for row, event in enumerate(display_events):
            created_at = str(event.get("created_at", ""))
            stage = str(event.get("stage", ""))
            phase = str(event.get("phase", ""))
            status = str(event.get("status", ""))
            progress = event.get("progress", 0)

            expected = event.get("expected_sha256")
            actual = event.get("actual_sha256")

            msg = str(event.get("message", ""))

            # Count successful integrity checkpoints only when
            # both hashes actually exist and match.
            if (
                status == "completed"
                and expected
                and actual
                and expected == actual
            ):
                passed_hash_checks += 1

            if status == "failed":
                failed_count += 1

            # Main table shows only a simple integrity result.
            if expected and actual:
                sha256_integrity = (
                    "✓ Match"
                    if expected == actual
                    else "✗ Mismatch"
                )
            else:
                sha256_integrity = "—"

            # Cleaner table timestamp.
            # The original full timestamp remains in the event data.
            timestamp_display = created_at.replace("T", " ")[:19]

            t_item = QTableWidgetItem(timestamp_display)
            s_item = QTableWidgetItem(stage)
            p_item = QTableWidgetItem(phase)
            st_item = QTableWidgetItem(status)
            pr_item = QTableWidgetItem(f"{progress}%")
            integrity_item = QTableWidgetItem(sha256_integrity)
            msg_item = QTableWidgetItem(msg)

            # Full values remain accessible via tooltips.
            t_item.setToolTip(created_at)
            msg_item.setToolTip(msg)

            if expected or actual:
                integrity_item.setToolTip(
                    f"Expected SHA-256:\n{expected or 'N/A'}\n\n"
                    f"Actual SHA-256:\n{actual or 'N/A'}"
                )

            # Easier visual scanning.
            st_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )
            pr_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )
            integrity_item.setTextAlignment(
                Qt.AlignmentFlag.AlignCenter
            )

            # Store the complete event for double-click details.
            t_item.setData(
                Qt.ItemDataRole.UserRole,
                event,
            )

            self.table.setItem(row, 0, t_item)
            self.table.setItem(row, 1, s_item)
            self.table.setItem(row, 2, p_item)
            self.table.setItem(row, 3, st_item)
            self.table.setItem(row, 4, pr_item)
            self.table.setItem(row, 5, integrity_item)
            self.table.setItem(row, 6, msg_item)

        if events:
            self.empty_state.hide()
        elif self.database:
            self.empty_state.setText(
                "No activity events found."
            )
            self.empty_state.show()
            self.empty_state.raise_()
    
        self.total_val.setText(str(total_count))
        self.integrity_val.setText(
            f"{passed_hash_checks} Passed"
        )
        self.failures_val.setText(
            f"{failed_count} Failed"
        )

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


def create_page():
    return ActivityPage()
