"""Recorded findings page backed by the workspace repositories."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
    QLineEdit,
    QMessageBox,
)

from memsentry.app.case_service import workspace_database
from memsentry.models.case import Case
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.finding_repository import FindingRepository
from memsentry.gui.controls import ThemedComboBox

class FindingCard(QFrame):
    clicked = Signal(object)

    def __init__(self, finding, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.finding = finding

        self.setObjectName("findingCard")
        self.setCursor(Qt.CursorShape.PointingHandCursor)

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
        layout.addWidget(self.status)

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

        self.findings_layout = QVBoxLayout()
        self.findings_layout.setSpacing(10)
        layout.addLayout(self.findings_layout)
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

        for finding in visible:
            card = FindingCard(finding)
            card.clicked.connect(self._show_finding_details)
            card.setToolTip("Click to view finding details")

            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(16, 12, 16, 12)
            card_layout.setSpacing(4)

            header = QHBoxLayout()

            title = QLabel(finding.title)
            title.setWordWrap(True)
            title.setObjectName("sectionTitle")
            title.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

            severity = QLabel(finding.severity.value.upper())
            severity.setObjectName("severityBadge")
            severity.setProperty("severity", finding.severity.value)
            severity.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)

            header.addWidget(title, 1)
            header.addWidget(
                severity,
                alignment=Qt.AlignmentFlag.AlignTop,
            )

            card_layout.addLayout(header)

            metadata = QLabel(
                f"Rule: {finding.rule_id} · Confidence: "
                + (
                    f"{finding.confidence:.0%}"
                    if finding.confidence is not None
                    else "Not recorded"
                )
            )
            metadata.setObjectName("muted")
            metadata.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            card_layout.addWidget(metadata)

            preview = finding.description

            if len(preview) > 220:
                preview = preview[:220].rstrip() + "…"

            description = QLabel(preview)
            description.setWordWrap(True)
            description.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
            card_layout.addWidget(description)
            graph_button = QPushButton("Explore relationships")
            graph_button.clicked.connect(
                lambda checked=False, item=finding: self.graph_requested.emit(
                    item.analysis_run_id, item.id
                )
            )
            card_layout.addWidget(graph_button)
            self.findings_layout.addWidget(card)

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
        while self.findings_layout.count():
            item = self.findings_layout.takeAt(0)
            if item is None:
                continue
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()


def create_page() -> FindingsPage:
    return FindingsPage()
