"""Readable, selectable finding details and stored provenance in one scrollable view."""

import json
from datetime import UTC
from html import escape

from PySide6.QtGui import QPalette, QTextOption
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QPushButton,
    QTextBrowser,
    QVBoxLayout,
    QWidget,
)

from memsentry.gui.cursors import InteractiveCursors
from memsentry.gui.theme import workspace_stylesheet
from memsentry.models.finding import Finding
from memsentry.models.finding_evidence import FindingEvidence


class FindingDetailsDialog(QDialog):
    def __init__(self, finding: Finding, evidence: list[FindingEvidence],
                 parent: QWidget | None = None, *, evidence_error: str = "") -> None:
        super().__init__(parent)
        self.setWindowTitle("Finding details")
        self.setObjectName("workspace")
        self.setStyleSheet(workspace_stylesheet())
        self.setSizeGripEnabled(True)
        screen = self.screen().availableGeometry()
        self.resize(min(900, screen.width() - 64), min(760, screen.height() - 80))
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 16)
        layout.setSpacing(16)
        self.details = QTextBrowser()
        self.details.setAccessibleName("Complete finding details and supporting evidence")
        self.details.setOpenLinks(False)
        self.details.setOpenExternalLinks(False)
        self.details.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        self.details.document().setDocumentMargin(24)
        dark = self.palette().color(QPalette.ColorRole.Window).lightness() < 128
        surface, text, muted, border = (
            ("#1B212B", "#E5E7EB", "#A5B0C0", "#303947") if dark else
            ("#FFFFFF", "#172033", "#526174", "#DCE3EC"))
        severity_colors = {
            "critical": "#F87171" if dark else "#B91C1C",
            "high": "#FB923C" if dark else "#9A3412",
            "medium": "#FACC15" if dark else "#785A00",
            "low": "#60A5FA" if dark else "#2563EB",
            "informational": muted,
        }
        self.details.setStyleSheet(
            f"QTextBrowser {{ background: {surface}; color: {text}; "
            f"border: 1px solid {border}; border-radius: 10px; }}")
        self.details.document().setDefaultStyleSheet(
            f"body {{ color: {text}; }} h1 {{ font-size: 24px; margin-bottom: 12px; }} "
            "h2 { font-size: 16px; margin-top: 24px; margin-bottom: 10px; } "
            f".muted {{ color: {muted}; }} td {{ padding: 6px 10px 6px 0; }} "
            "p { line-height: 140%; } pre { white-space: pre-wrap; }")
        confidence = f"{finding.confidence:.0%}" if finding.confidence is not None else "Not recorded"
        created = finding.created_at
        if created.tzinfo is None:
            created = created.replace(tzinfo=UTC)
        fields = [
            ("Rule", finding.rule_id), ("Confidence", confidence),
            ("Created (UTC)", created.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S")),
            ("Finding ID", str(finding.id)), ("Analysis run", str(finding.analysis_run_id)),
        ]
        parts = [f"<h1>{escape(finding.title)}</h1>",
                 f'<p style="color: {severity_colors[finding.severity.value]}">'
                 f"<b>{finding.severity.value.upper()} SEVERITY</b></p>",
                 "<h2>Description</h2>", self._paragraph(finding.description),
                 "<h2>Finding record</h2>", "<table width='100%'>"]
        for label, value in fields:
            parts.append(f"<tr><td class='muted' width='150'>{label}</td>"
                         f"<td>{escape(value)}</td></tr>")
        parts.extend(["</table>", "<p class='muted'>Confidence is the recorded rule confidence, "
                      "not a probability that the process is malicious.</p>",
                      f"<h2>Supporting evidence ({len(evidence)})</h2>"])
        if evidence_error:
            parts.append(self._paragraph(evidence_error))
        elif not evidence:
            parts.append("<p class='muted'>No supporting evidence links were recorded for this finding.</p>")
        for index, item in enumerate(evidence, 1):
            parts.extend([
                f"<h2>{index}. {escape(item.artifact_type or 'Recorded evidence')}</h2>",
                self._paragraph(item.explanation),
                self._paragraph(f"Source reference: {item.source_reference or 'Not recorded'}"),
                self._paragraph(f"Plugin run: {item.plugin_run_id}"),
                self._paragraph(f"Evidence link ID: {item.id}"),
                "<pre>" + escape(json.dumps(item.supporting_data, indent=2, ensure_ascii=False)) + "</pre>",
            ])
        self.details.setHtml("".join(parts))
        layout.addWidget(self.details, 1)
        actions = QHBoxLayout()
        copy = QPushButton("Copy details")
        copy.clicked.connect(lambda: QApplication.clipboard().setText(self.details.toPlainText()))
        actions.addWidget(copy)
        actions.addStretch()
        close = QPushButton("Close")
        close.setObjectName("primaryAction")
        close.clicked.connect(self.accept)
        close.setDefault(True)
        actions.addWidget(close)
        layout.addLayout(actions)
        self._interactive_cursors = InteractiveCursors(self)

    @staticmethod
    def _paragraph(text: str) -> str:
        return "<p>" + escape(text).replace("\n", "<br>") + "</p>"
