"""Export findings with provenance and integrity records."""

import logging
from pathlib import Path

from PySide6.QtCore import QSettings, Qt
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QCheckBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
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
from memsentry.reports.signer import ReportSigningService
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
        self.refresh()

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
        self.format_group = QButtonGroup(self)
        self.both_radio = QRadioButton("Both (HTML & JSON)")
        self.html_radio = QRadioButton("HTML (Readable report)")
        self.json_radio = QRadioButton("JSON (Structured results)")
        self.format_group.addButton(self.both_radio)
        self.format_group.addButton(self.html_radio)
        self.format_group.addButton(self.json_radio)
        self.both_radio.setChecked(True)
        form_layout.addWidget(self.both_radio)
        form_layout.addWidget(self.html_radio)
        form_layout.addWidget(self.json_radio)

        # Output Destination
        form_layout.addWidget(label("Destination directory", "sectionTitle"))
        out_row = QHBoxLayout()
        self.output_dir_input = QLineEdit()
        self.output_dir_input.setPlaceholderText("Select destination directory for reports...")
        out_row.addWidget(self.output_dir_input)
        browse_out_btn = QPushButton("Browse…")
        browse_out_btn.clicked.connect(self._browse_output_dir)
        out_row.addWidget(browse_out_btn)
        form_layout.addLayout(out_row)

        output_hint = label(
            "Defaults to your configured reporting path in Settings (or case workspace).",
            "muted",
        )
        form_layout.addWidget(output_hint)

        # Sections
        form_layout.addWidget(label("Report contents", "sectionTitle"))

        mandatory_label = label(
            "Mandatory sections: Case summary, Evidence & integrity, Findings summary", "muted"
        )
        form_layout.addWidget(mandatory_label)

        self.chk_plugins = QCheckBox("Plugin execution summary")
        self.chk_artifacts = QCheckBox("Artifacts (Warning: can be large)")
        self.chk_workflow = QCheckBox("Workflow and audit history")
        self.chk_sign = QCheckBox("Digitally sign exported reports")

        form_layout.addWidget(self.chk_plugins)
        form_layout.addWidget(self.chk_artifacts)
        form_layout.addWidget(self.chk_workflow)
        form_layout.addWidget(self.chk_sign)

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

    def refresh(self) -> None:
        """Reload configuration defaults from QSettings."""
        qsettings = QSettings("MemSentry", "MemSentry")
        default_format = str(qsettings.value("reporting/format", "both")).lower().strip()
        if default_format == "html":
            self.html_radio.setChecked(True)
        elif default_format == "json":
            self.json_radio.setChecked(True)
        else:
            self.both_radio.setChecked(True)

        default_out = str(qsettings.value("reporting/output_directory", "")).strip()
        if default_out:
            self.output_dir_input.setText(default_out)
        elif self.workspace_path and not self.output_dir_input.text().strip():
            self.output_dir_input.setText(self.workspace_path)

        sign_default = str(qsettings.value("reporting/sign_reports", "false")).lower() in (
            "true",
            "1",
        )
        self.chk_sign.setChecked(sign_default)

    def _browse_output_dir(self) -> None:
        current = self.output_dir_input.text().strip() or self.workspace_path
        path = QFileDialog.getExistingDirectory(self, "Select Output Directory", current)
        if path:
            self.output_dir_input.setText(path)

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

        self.refresh()

    def _generate_report(self) -> None:
        if not self.case or not self.database:
            return

        out_dir_str = self.output_dir_input.text().strip()
        if not out_dir_str:
            qsettings = QSettings("MemSentry", "MemSentry")
            out_dir_str = str(qsettings.value("reporting/output_directory", "")).strip()

        if not out_dir_str and self.workspace_path:
            out_dir_str = self.workspace_path

        if not out_dir_str:
            out_dir_str = QFileDialog.getExistingDirectory(self, "Select Output Directory")
            if not out_dir_str:
                return
            self.output_dir_input.setText(out_dir_str)

        output_dir = Path(out_dir_str)
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            QMessageBox.critical(self, "Error", f"Could not create output directory:\n{exc}")
            return

        is_both = self.both_radio.isChecked()
        is_html = self.html_radio.isChecked() or is_both
        is_json = self.json_radio.isChecked() or is_both

        html_path = output_dir / f"MemSentry-Report-{self.case.case_number}.html"
        json_path = output_dir / f"MemSentry-Report-{self.case.case_number}.json"

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

            generated_files: list[Path] = []
            signer = ReportSigningService() if self.chk_sign.isChecked() else None

            if is_html:
                HtmlReportExporter().export(report_data, html_path)
                generated_files.append(html_path)
                if signer:
                    sig_path = signer.sign_file(html_path)
                    generated_files.append(sig_path)
            if is_json:
                JsonReportExporter().export(report_data, json_path)
                generated_files.append(json_path)
                if signer:
                    sig_path = signer.sign_file(json_path)
                    generated_files.append(sig_path)

            file_list = "\n".join(f"• {p.name}" for p in generated_files)
            format_desc = "HTML & JSON" if is_both else ("HTML" if is_html else "JSON")
            signed_suffix = " (digitally signed)" if signer else ""
            self.status_label.setText(f"✓ {format_desc} report(s){signed_suffix} saved to {output_dir.name}")
            QMessageBox.information(
                self,
                "Report Generated",
                f"Successfully exported report(s) to:\n{output_dir}\n\n{file_list}",
            )

        except Exception as exc:
            logger.exception("Failed to generate report")
            self.status_label.setText(f"❌ Failed to generate report: {exc}")
            QMessageBox.critical(self, "Error", f"Failed to generate report:\n{exc}")


def create_page() -> ReportsPage:
    return ReportsPage()
