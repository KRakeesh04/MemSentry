"""Case dashboard showing recorded evidence, runs, and findings."""

from PySide6.QtCore import Qt, QTimer, Signal
from PySide6.QtWidgets import (
    QBoxLayout,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from memsentry.app.case_service import workspace_database
from memsentry.gui.controls import ThemedComboBox
from memsentry.gui.intake_widgets import ChoiceCard
from memsentry.gui.workflow_stepper import WorkflowStepper
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.finding_repository import FindingRepository
from memsentry.storage.repositories.workflow_repository import WorkflowRepository


def label(text: str, style: str = "") -> QLabel:
    widget = QLabel(text)
    widget.setTextFormat(Qt.TextFormat.PlainText)
    widget.setWordWrap(True)
    widget.setObjectName(style)
    widget.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
    return widget


def clear_layout(layout):
    while layout.count():
        item = layout.takeAt(0)
        if item.widget():
            item.widget().deleteLater()


class OverviewPage(QScrollArea):
    import_requested = Signal()
    cases_requested = Signal()
    case_opened = Signal(str, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.case = None
        self.workspace_path = ""
        self.database = None
        self._intake_active = False
        self._intake_error = None
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(20)
        layout.addWidget(label("INVESTIGATION OVERVIEW", "muted"))
        self.title = label("No case selected", "pageTitle")
        layout.addWidget(self.title)
        self.subtitle = label("Open or create a case to view its evidence and findings.", "muted")
        layout.addWidget(self.subtitle)
        actions = QHBoxLayout()
        self.import_button = QPushButton("Add memory evidence")
        self.import_button.setObjectName("primaryAction")
        self.import_button.setEnabled(False)
        self.import_button.clicked.connect(self.import_requested.emit)
        actions.addWidget(self.import_button)
        cases = QPushButton("Browse cases")
        cases.clicked.connect(self.cases_requested.emit)
        actions.addWidget(cases)
        refresh = QPushButton("Refresh overview")
        refresh.clicked.connect(self.refresh)
        actions.addWidget(refresh)
        actions.addStretch()
        layout.addLayout(actions)
        self.error = label("")
        layout.addWidget(self.error)
        columns = QHBoxLayout()
        self.columns = columns
        main = QVBoxLayout()
        main.setSpacing(16)
        evidence_card = QFrame()
        evidence_card.setObjectName("card")
        evidence_layout = QVBoxLayout(evidence_card)
        evidence_layout.setContentsMargins(20, 20, 20, 20)
        evidence_layout.addWidget(label("Memory evidence", "sectionTitle"))
        self.evidence_choice = ThemedComboBox()
        self.evidence_choice.setPlaceholderText("No evidence registered")
        self.evidence_choice.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.evidence_choice.setMinimumContentsLength(16)
        self.evidence_choice.setAccessibleName("Evidence image")
        self.evidence_choice.currentIndexChanged.connect(self._evidence_changed)
        evidence_layout.addWidget(self.evidence_choice)
        self.integrity = label("No evidence registered", "muted")
        evidence_layout.addWidget(self.integrity)
        self.details = label("Add a memory image to begin.")
        evidence_layout.addWidget(self.details)
        self.hash = label("", "muted")
        self.hash.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        evidence_layout.addWidget(self.hash)
        main.addWidget(evidence_card)
        main.addWidget(label("Analysis history", "sectionTitle"))
        self.run_choice = ThemedComboBox()
        self.run_choice.setPlaceholderText("No analysis runs recorded")
        self.run_choice.setSizeAdjustPolicy(
            QComboBox.SizeAdjustPolicy.AdjustToMinimumContentsLengthWithIcon
        )
        self.run_choice.setMinimumContentsLength(16)
        self.run_choice.setAccessibleName("Analysis run")
        self.run_choice.currentIndexChanged.connect(self._run_changed)
        main.addWidget(self.run_choice)
        self.run_status = label("No recorded analysis", "muted")
        main.addWidget(self.run_status)
        main.addWidget(label("Recorded findings", "sectionTitle"))
        self.findings_layout = QVBoxLayout()
        main.addLayout(self.findings_layout)
        main.addStretch()
        main_widget = QWidget()
        main_widget.setLayout(main)
        columns.addWidget(main_widget, 4)
        recent_card = QFrame()
        self.recent_card = recent_card
        recent_card.setObjectName("card")
        recent_card.setMaximumWidth(280)
        recent_layout = QVBoxLayout(recent_card)
        recent_layout.setContentsMargins(16, 20, 16, 20)
        recent_layout.addWidget(label("Recent cases", "sectionTitle"))
        self.recent_layout = QVBoxLayout()
        recent_layout.addLayout(self.recent_layout)
        recent_layout.addStretch()
        columns.addWidget(recent_card, 1)
        layout.addLayout(columns)
        self.workflow = WorkflowStepper()
        layout.addWidget(self.workflow)
        self.setWidget(content)
        self.workflow_timer = QTimer(self)
        self.workflow_timer.setInterval(1000)
        self.workflow_timer.timeout.connect(self._poll_workflow)
        self.workflow_timer.start()

    def open_case(self, workspace, case):
        self._intake_active = False
        self.workspace_path = workspace
        self.case = case
        self.refresh()

    def resizeEvent(self, event):
        super().resizeEvent(event)
        narrow = self.viewport().width() < 800
        self.columns.setDirection(
            QBoxLayout.Direction.TopToBottom if narrow else QBoxLayout.Direction.LeftToRight
        )
        self.recent_card.setMaximumWidth(16777215 if narrow else 280)

    def refresh(self):
        self._intake_active = False
        self._intake_error = None
        if self.case is None:
            return
        self.error.clear()
        self.import_button.setEnabled(False)
        try:
            self.database = workspace_database(self.workspace_path)
            if not self.database.database_path.is_file():
                raise ValueError("The workspace database is no longer available.")
            case = CaseRepository(self.database).get_by_id(self.case.id)
            if case is None:
                raise ValueError("The selected case is no longer available.")
            self.case = case
            self.title.setText(case.name)
            self.subtitle.setText(
                f"{case.case_number} · {case.status.title()} · "
                f"Created {case.created_at:%Y-%m-%d %H:%M} UTC\n{case.description or ''}"
            )
            selected = self.evidence_choice.currentData()
            self.evidence_choice.blockSignals(True)
            self.evidence_choice.clear()
            for evidence in EvidenceRepository(self.database).list_by_case(case.id):
                self.evidence_choice.addItem(evidence.original_filename, evidence)
                if selected and selected.id == evidence.id:
                    self.evidence_choice.setCurrentIndex(self.evidence_choice.count() - 1)
            if self.evidence_choice.count() and self.evidence_choice.currentIndex() < 0:
                self.evidence_choice.setCurrentIndex(0)
            self.evidence_choice.blockSignals(False)
            self._evidence_changed()
            clear_layout(self.recent_layout)
            for recent in CaseRepository(self.database).list_all()[:6]:
                button = ChoiceCard(recent.name, f"{recent.case_number} · {recent.status.title()}")
                button.setChecked(recent.id == case.id)
                button.setToolTip(recent.name)
                button.clicked.connect(
                    lambda checked=False, item=recent: self.case_opened.emit(
                        self.workspace_path, item
                    )
                )
                self.recent_layout.addWidget(button)
            self.import_button.setEnabled(case.status == "open")
        except Exception as exc:
            self.evidence_choice.blockSignals(False)
            self.error.setText(f"Could not load overview: {exc}")
            self.evidence_choice.clear()
            clear_layout(self.recent_layout)

    def _evidence_changed(self):
        evidence = self.evidence_choice.currentData()
        self.run_choice.blockSignals(True)
        self.run_choice.clear()
        self.integrity.setObjectName("muted")
        if evidence is None:
            self.integrity.setText("No evidence registered")
            self.details.setText("Add a memory image to begin.")
            self.hash.clear()
        else:
            verified = evidence.integrity_status == "verified"
            self.integrity.setObjectName("verified" if verified else "integrityWarning")
            self.integrity.setText(
                f"{'✓' if verified else '!'} SHA-256 · Last recorded: {evidence.integrity_status}"
            )
            self.details.setText(
                f"OS: {evidence.evidence_os or 'Not identified'}  ·  "
                f"Image size: {evidence.file_size_bytes / 1024**3:.2f} GiB\n"
                f"Registered: {evidence.registered_at:%Y-%m-%d %H:%M} UTC\n"
                f"Path: {evidence.file_path}"
            )
            self.hash.setText(f"SHA-256 baseline\n{evidence.sha256}")
            try:
                for run in AnalysisRunRepository(self.database).list_by_evidence(evidence.id):
                    self.run_choice.addItem(
                        f"{run.created_at:%Y-%m-%d %H:%M} UTC · {run.status} · {str(run.id)[:8]}",
                        run,
                    )
            except Exception as exc:
                self.error.setText(f"Could not load analysis history: {exc}")
        if self.run_choice.count():
            self.run_choice.setCurrentIndex(0)
        self.integrity.style().unpolish(self.integrity)
        self.integrity.style().polish(self.integrity)
        self.run_choice.blockSignals(False)
        self._run_changed()

    def _run_changed(self):
        clear_layout(self.findings_layout)
        run = self.run_choice.currentData()
        findings = []
        findings_error = False
        self.run_status.setText("No recorded analysis — absence of findings does not mean clean.")
        if run is not None:
            self.run_status.setText(
                f"Run: {run.id}\nStatus: {run.status}\n{run.error_message or ''}"
            )
            try:
                findings = FindingRepository(self.database).list_by_analysis_run(run.id)
            except Exception as exc:
                findings_error = True
                self.error.setText(f"Could not load findings: {exc}")
        severity_order = {
            value: index
            for index, value in enumerate(["critical", "high", "medium", "low", "informational"])
        }
        for finding in sorted(findings, key=lambda item: severity_order[item.severity]):
            confidence = (
                f"{finding.confidence:.0%}" if finding.confidence is not None else "Not recorded"
            )
            button = ChoiceCard(
                f"{finding.severity.upper()} · {finding.title}",
                f"{finding.rule_id} · Confidence: {confidence}",
            )
            button.setCheckable(False)
            button.setProperty("severity", finding.severity.value)
            button.setToolTip("Open finding details and provenance identifiers")
            button.clicked.connect(lambda checked=False, item=finding: self._show_finding(item))
            self.findings_layout.addWidget(button)
        if not findings:
            self.findings_layout.addWidget(
                label(
                    "Findings unavailable — the database could not be read."
                    if findings_error
                    else "No findings recorded for this run."
                    if run
                    else "Findings will appear here when an analysis saves results.",
                    "muted",
                )
            )
        self._refresh_workflow()

    def _poll_workflow(self):
        if self.isVisible() and not self._intake_active:
            self._refresh_workflow()

    def show_intake_progress(self, message, value):
        self._intake_active = True
        self._intake_error = None
        self.workflow.show_records(self.case, None, None, [])
        self.workflow.states[1] = "running"
        if message == "Verifying evidence SHA-256":
            self.workflow.states[1] = "completed"
            self.workflow.states[2] = "running"
            self.workflow.checkpoints[1] = "running"
        self.workflow.detail.setText(
            f"New evidence intake · {message}" + (f" · {value}%" if value >= 0 else ""))
        self.workflow._paint_states()

    def finish_intake_progress(self):
        if self._intake_error:
            return
        self._intake_active = False
        self._refresh_workflow()

    def show_intake_failure(self, message):
        if not self._intake_active:
            return
        self._intake_error = message
        index = 2 if self.workflow.states[2] == "running" else 1
        self.workflow.states[index] = "failed"
        if index == 2:
            self.workflow.checkpoints[1] = "failed"
        self.workflow.detail.setText(f"Evidence intake stopped · {message}")
        self.workflow._paint_states()

    def _refresh_workflow(self):
        evidence = self.evidence_choice.currentData()
        run = self.run_choice.currentData()
        events = []
        try:
            if evidence and self.database:
                evidence = EvidenceRepository(self.database).get_by_id(evidence.id)
                if evidence:
                    if run:
                        run = AnalysisRunRepository(self.database).get_by_id(run.id)
                    elif self.isVisible():
                        runs = AnalysisRunRepository(self.database).list_by_evidence(evidence.id)
                        if runs:
                            self._evidence_changed()
                            return
                    events = WorkflowRepository(self.database).list_events(
                        evidence.id, run.id if run else None)
            self.workflow.show_records(self.case, evidence, run, events)
        except Exception as exc:
            self.workflow.show_records(None, None, None, [])
            self.workflow.detail.setText(f"Workflow status unavailable: {exc}")

    def _show_finding(self, finding):
        dialog = QMessageBox(self)
        dialog.setWindowTitle("Finding details")
        dialog.setTextFormat(Qt.TextFormat.PlainText)
        dialog.setText(f"{finding.title}\n\n{finding.description}")
        dialog.setDetailedText(
            f"Finding: {finding.id}\nRule: {finding.rule_id}\nRun: {finding.analysis_run_id}\n"
            f"Severity: {finding.severity}\nConfidence: {finding.confidence}\n"
            "Recorded findings are triage indicators, not a verdict of malicious activity."
        )
        dialog.exec()


def create_page():
    return OverviewPage()
