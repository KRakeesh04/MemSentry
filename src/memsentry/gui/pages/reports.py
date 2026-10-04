"""Export findings with provenance and integrity records."""

import logging
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QRadioButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from memsentry.app.case_service import workspace_database
from memsentry.app.report_service import ReportService
from memsentry.models.case import Case
from memsentry.models.report import ReportOptions
from memsentry.reports.exporters.html_exporter import HtmlReportExporter
from memsentry.reports.exporters.json_exporter import JsonReportExporter
from memsentry.storage.database import Database
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.finding_repository import FindingRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
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


class ReportsPage(QScrollArea):
    """Reports page for generating and exporting forensic case reports."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.case: Case | None = None
        self.workspace_path = ""
        self.database: Database | None = None

        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        self._build_ui()

    def _build_ui(self) -> None:
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(20)

        layout.addWidget(label("EXPORT & REPORTING", "muted"))
        self.title = label("Reports", "pageTitle")
        layout.addWidget(self.title)
        self.subtitle = label(
            "Export findings with provenance and integrity records.",
            "muted",
        )
        layout.addWidget(self.subtitle)

        # Form Container
        self.form = QFrame()
        self.form.setObjectName("card")
        form_layout = QVBoxLayout(self.form)
        form_layout.setContentsMargins(24, 24, 24, 24)
        form_layout.setSpacing(16)

        # Format Selection
        form_layout.addWidget(label("Format", "sectionTitle"))
        self.html_radio = QRadioButton("HTML (Readable report)")
        self.json_radio = QRadioButton("JSON (Structured results)")
        self.html_radio.setChecked(True)
        form_layout.addWidget(self.html_radio)
        form_layout.addWidget(self.json_radio)

        # Sections
        form_layout.addWidget(label("Report contents", "sectionTitle"))

        mandatory_label = label(
            "Mandatory sections: Case summary, Evidence & integrity, Findings summary", "muted"
        )
        form_layout.addWidget(mandatory_label)

        self.chk_plugins = QCheckBox("Plugin execution summary")
        self.chk_artifacts = QCheckBox("Artifacts (Warning: can be large)")
        self.chk_workflow = QCheckBox("Workflow and audit history")

        form_layout.addWidget(self.chk_plugins)
        form_layout.addWidget(self.chk_artifacts)
        form_layout.addWidget(self.chk_workflow)

        layout.addWidget(self.form)

        # Action Buttons
        actions = QHBoxLayout()
        self.btn_generate = QPushButton("Generate report")
        self.btn_generate.setObjectName("primaryAction")
        self.btn_generate.clicked.connect(self._generate_report)
        self.btn_generate.setEnabled(False)

        actions.addWidget(self.btn_generate)
        actions.addStretch()
        layout.addLayout(actions)

        self.status_label = label("")
        layout.addWidget(self.status_label)
        layout.addStretch()

        self.setWidget(content)

    def open_case(self, workspace_path: str, case: Case | None) -> None:
        self.workspace_path = workspace_path
        self.case = case

        if workspace_path:
            self.database = workspace_database(workspace_path)
        else:
            self.database = None

        has_case = self.database is not None and self.case is not None
        self.btn_generate.setEnabled(has_case)
        self.title.setText(f"Reports · {case.case_number if case else ''}")
        self.status_label.setText("")

    def _generate_report(self) -> None:
        if not self.case or not self.database:
            return

        is_html = self.html_radio.isChecked()
        ext = ".html" if is_html else ".json"
        filter_str = "HTML Files (*.html)" if is_html else "JSON Files (*.json)"
        default_name = f"MemSentry-Report-{self.case.case_number}{ext}"

        file_path, _ = QFileDialog.getSaveFileName(self, "Save Report", default_name, filter_str)

        if not file_path:
            return

        try:
            self.status_label.setText("Gathering report data...")
            QApplication.processEvents()

            options = ReportOptions(
                include_plugin_runs=self.chk_plugins.isChecked(),
                include_artifacts=self.chk_artifacts.isChecked(),
                include_workflow_history=self.chk_workflow.isChecked(),
            )

            service = ReportService(
                case_repo=CaseRepository(self.database),
                evidence_repo=EvidenceRepository(self.database),
                analysis_run_repo=AnalysisRunRepository(self.database),
                plugin_run_repo=PluginRunRepository(self.database),
                finding_repo=FindingRepository(self.database),
                artifact_repo=ArtifactRepository(self.database),
                workflow_repo=WorkflowRepository(self.database),
            )

            report_data = service.aggregate_report_data(self.case.id, options)

            self.status_label.setText("Exporting report...")
            QApplication.processEvents()

            output_path = Path(file_path)
            if is_html:
                HtmlReportExporter().export(report_data, output_path)
            else:
                JsonReportExporter().export(report_data, output_path)

            self.status_label.setText(f"✓ Report successfully generated: {output_path.name}")
            QMessageBox.information(
                self, "Success", f"Report saved successfully to:\n{output_path}"
            )

        except Exception as exc:
            logger.exception("Failed to generate report")
            self.status_label.setText(f"❌ Failed to generate report: {exc}")
            QMessageBox.critical(self, "Error", f"Failed to generate report:\n{exc}")


def create_page() -> ReportsPage:
    return ReportsPage()
