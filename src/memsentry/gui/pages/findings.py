"""Recorded findings page backed by the workspace repositories."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QEvent, Qt, QTimer, Signal
from PySide6.QtGui import QKeyEvent
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from memsentry.app.case_service import workspace_database
from memsentry.gui.controls import ThemedComboBox
from memsentry.models.case import Case
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.finding_repository import FindingRepository


class FindingCard(QFrame):
    clicked = Signal(object)

    def __init__(self, finding, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.finding = finding

        self.setObjectName("findingCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.setAccessibleName(f"{finding.title}. {finding.severity.value}. Open finding details")

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter, Qt.Key.Key_Space):
            self.clicked.emit(self.finding)
            event.accept()
            return
        super().keyPressEvent(event)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit(self.finding)

        super().mousePressEvent(event)

class FindingsPage(QScrollArea):
    """Show findings persisted for the currently opened case."""

    graph_requested = Signal(object, object)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.workspace_path = ""
        self.case: Case | None = None
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        self.findings = []
        self._cards: list[FindingCard] = []
        self._reflow_timer = QTimer(self)
        self._reflow_timer.setSingleShot(True)
        self._reflow_timer.timeout.connect(self._reflow_cards)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(16)

        heading = QHBoxLayout()
        title = QLabel("Findings")
        title.setObjectName("pageTitle")
        heading.addWidget(title)
        heading.addStretch()
        self.refresh_button = QPushButton("Refresh findings")
        self.refresh_button.clicked.connect(self.refresh)
        heading.addWidget(self.refresh_button)
        layout.addLayout(heading)

        self.subtitle = QLabel("Open a case to review recorded analysis findings.")
        self.subtitle.setObjectName("muted")
        self.subtitle.setWordWrap(True)
        layout.addWidget(self.subtitle)

        self.status = QLabel("No case selected.")
        self.status.setWordWrap(True)
        self.status.setObjectName("muted")

        filters = QHBoxLayout()

        self.search = QLineEdit()
        self.search.setPlaceholderText("Search findings")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._render_findings)
        filters.addWidget(self.search, 1)

        self.severity_filter = ThemedComboBox()
        self.severity_filter.addItems(
            ["All severities", "Critical", "High", "Medium", "Low", "Informational"]
        )
        self.severity_filter.currentIndexChanged.connect(self._render_findings)
        filters.addWidget(self.severity_filter)

        layout.addLayout(filters)
        layout.addWidget(self.status)

        self.findings_container = QWidget()
        self.findings_container.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.findings_layout = QGridLayout(self.findings_container)
        self.findings_layout.setContentsMargins(0, 0, 0, 0)
        self.findings_layout.setSpacing(16)
        self.findings_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        layout.addWidget(self.findings_container)
        self.empty_state = QLabel("No findings yet. Run an analysis to review its results here.")
        self.empty_state.setObjectName("muted")
        self.empty_state.setWordWrap(True)
        layout.addWidget(self.empty_state)
        layout.addStretch()
        self.setWidget(content)

    def open_case(self, workspace: str, case: Case) -> None:
        """Set the selected case and reload findings from its workspace database."""
        self.workspace_path = workspace
        self.case = case
        self.refresh()

    def refresh(self) -> None:
        """Reload findings persisted for the selected case."""
        self._clear_findings()
        self.findings = []
        self.empty_state.setText("No findings yet. Run an analysis to review its results here.")
        self.empty_state.show()
        if self.case is None or not self.workspace_path:
            self.status.setText("No case selected.")
            return

        self.subtitle.setText(
            f"{self.case.case_number} · {self.case.name} · Recorded analysis findings"
        )
        try:
            database = workspace_database(Path(self.workspace_path))
            evidence_records = EvidenceRepository(database).list_by_case(self.case.id)
            analysis_runs = [
                run
                for evidence in evidence_records
                for run in AnalysisRunRepository(database).list_by_evidence(evidence.id)
            ]
            findings = [
                finding
                for run in analysis_runs
                for finding in FindingRepository(database).list_by_analysis_run(run.id)
            ]
        except Exception as exc:
            self.status.setText(f"Could not load findings: {exc}")
            return

        if not findings:
            self.findings = []
            self.status.setText("No findings recorded for this case.")
            return

        severity_order = {
            "critical": 0,
            "high": 1,
            "medium": 2,
            "low": 3,
            "informational": 4,
        }

        findings.sort(
            key=lambda item: (
                severity_order[item.severity.value],
                item.created_at,
            )
        )

        self.findings = findings
        self._render_findings()

    def _render_findings(self) -> None:
        self._clear_findings()

        query = self.search.text().strip().casefold()
        selected_severity = self.severity_filter.currentText().lower()

        visible = [
            finding
            for finding in self.findings
            if (
                self.severity_filter.currentIndex() == 0
                or finding.severity.value == selected_severity
            )
            and query in (
                f"{finding.title} "
                f"{finding.rule_id} "
                f"{finding.description}"
            ).casefold()
        ]

        self.status.setText(
            f"{len(visible)} of {len(self.findings)} finding(s) shown."
        )
        self.empty_state.setVisible(not visible)
        if not visible:
            self.empty_state.setText("No matching findings. Try another search or severity.")

        for finding in visible:
            card = FindingCard(finding)
            card.clicked.connect(self._show_finding_details)
            card.setToolTip("Click to view finding details")

            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(20, 16, 20, 16)
            card_layout.setSpacing(10)

            header = QHBoxLayout()

            title = QLabel(finding.title)
            title.setWordWrap(True)
            title.setTextFormat(Qt.TextFormat.PlainText)
            title.setMinimumWidth(0)
            title.setObjectName("sectionTitle")
            title.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

            severity = QLabel(finding.severity.value.upper())
            severity.setObjectName("severityBadge")
            severity.setProperty("severity", finding.severity.value)
            severity.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

            rule = QLabel(finding.rule_id)
            rule.setObjectName("muted")
            rule.setTextFormat(Qt.TextFormat.PlainText)
            rule.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            header.addWidget(rule, 1)
            header.addWidget(
                severity,
                alignment=Qt.AlignmentFlag.AlignTop,
            )

            card_layout.addLayout(header)
            card_layout.addWidget(title)

            metadata = QLabel(
                "Confidence: "
                + (
                    f"{finding.confidence:.0%}"
                    if finding.confidence is not None
                    else "Not recorded"
                )
            )
            metadata.setObjectName("muted")
            metadata.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

            preview = finding.description

            if len(preview) > 220:
                preview = preview[:220].rstrip() + "…"

            description = QLabel(preview)
            description.setTextFormat(Qt.TextFormat.PlainText)
            description.setWordWrap(True)
            description.setMinimumWidth(0)
            description.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            card_layout.addWidget(description)
            card_layout.addStretch()
            footer = QHBoxLayout()
            footer.addWidget(metadata)
            footer.addStretch()
            details_hint = QLabel("View details →")
            details_hint.setObjectName("findingDetailsHint")
            details_hint.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            footer.addWidget(details_hint)
            card_layout.addLayout(footer)
            self._cards.append(card)
        self._reflow_cards()

    def viewportEvent(self, event: QEvent) -> bool:
        if event.type() == QEvent.Type.Resize and hasattr(self, "_reflow_timer"):
            self._reflow_timer.start(0)
        return super().viewportEvent(event)

    def _reflow_cards(self) -> None:
        width = max(1, self.viewport().width() - 64)
        columns = max(1, min(3, (width + 16) // 476))
        while self.findings_layout.count():
            self.findings_layout.takeAt(0)
        for column in range(3):
            self.findings_layout.setColumnStretch(column, 1 if column < columns else 0)
        card_width = max(1, (width - 16 * (columns - 1)) // columns)
        for start in range(0, len(self._cards), columns):
            row = self._cards[start:start + columns]
            # Qt's old size hint can reflect the previous column width after a resize.
            # Measure wrapped content at its new width before assigning row heights.
            height = max(200, *(card.layout().totalHeightForWidth(card_width) for card in row))
            for offset, card in enumerate(row):
                card.setFixedHeight(height)
                self.findings_layout.addWidget(card, start // columns, offset)
        self.findings_layout.invalidate()
        self.findings_container.updateGeometry()

    def _show_finding_details(self, finding) -> None:
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Finding details")
        dialog.setTextFormat(Qt.TextFormat.PlainText)

        confidence = (
            f"{finding.confidence:.0%}"
            if finding.confidence is not None
            else "Not recorded"
        )

        dialog.setText(
            f"{finding.title}\n\n"
            f"{finding.description}"
        )

        dialog.setDetailedText(
            f"Finding ID: {finding.id}\n"
            f"Rule: {finding.rule_id}\n"
            f"Severity: {finding.severity.value}\n"
            f"Confidence: {confidence}\n"
            f"Analysis run: {finding.analysis_run_id}\n"
            f"Created: {finding.created_at:%Y-%m-%d %H:%M} UTC"
        )

        dialog.exec()

    def _clear_findings(self) -> None:
        self._cards.clear()
        while self.findings_layout.count():
            item = self.findings_layout.takeAt(0)
            if item is None:
                continue
            widget = item.widget()
            if widget is not None:
                widget.hide()
                widget.deleteLater()


def create_page() -> FindingsPage:
    return FindingsPage()
