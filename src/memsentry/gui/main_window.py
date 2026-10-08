"""Minimal application shell and sidebar navigation."""

from pathlib import Path

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QApplication,
    QDialog,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from memsentry.app.intake_service import IntakeResult
from memsentry.gui.analysis_dialog import AnalysisDialog, AnalysisWorker
from memsentry.gui.branding import application_icon
from memsentry.gui.cursors import InteractiveCursors
from memsentry.gui.pages import PLACEHOLDER_PAGES
from memsentry.gui.pages.activity import ActivityPage
from memsentry.gui.pages.artifacts import ArtifactsPage
from memsentry.gui.pages.cases import CasesPage
from memsentry.gui.pages.evidence import EvidencePage
from memsentry.gui.pages.findings import FindingsPage
from memsentry.gui.pages.investigation_graph import InvestigationGraphPage
from memsentry.gui.pages.overview import OverviewPage
from memsentry.gui.pages.reports import ReportsPage
from memsentry.gui.sidebar import Sidebar
from memsentry.gui.theme import workspace_stylesheet
from memsentry.models.analysis_run import AnalysisRun
from memsentry.models.case import Case
from memsentry.storage.database import Database
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.workflow_repository import WorkflowRepository


class MainWindow(QMainWindow):
    """Host the application pages using the platform's native window controls."""

    PAGE_NAMES = (
        "Cases",
        "Overview",
        "Evidence & Analysis",
        "Artifacts",
        "Findings",
        "Investigation Graph",
        "Reports",
        "Activity",
        "Settings",
        "Help",
    )

    def __init__(self) -> None:
        super().__init__()
        self.analysis_worker: AnalysisWorker | None = None
        self.analysis_run: AnalysisRun | None = None
        self.setWindowTitle("MemSentry")
        self.setWindowIcon(application_icon())
        self.resize(1100, 720)
        self.setMinimumSize(640, 480)
        self.setWindowFlags(
            Qt.WindowType.Window
            | Qt.WindowType.WindowTitleHint
            | Qt.WindowType.WindowSystemMenuHint
            | Qt.WindowType.WindowMinMaxButtonsHint
            | Qt.WindowType.WindowCloseButtonHint
        )

        container = QWidget(self)
        layout = QHBoxLayout(container)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.sidebar = Sidebar(self.PAGE_NAMES, container)
        layout.addWidget(self.sidebar)

        self.workspace = QWidget(container)
        self.workspace.setObjectName("workspace")
        self.workspace.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        workspace_layout = QVBoxLayout(self.workspace)
        workspace_layout.setContentsMargins(0, 0, 0, 0)
        workspace_layout.setSpacing(0)
        preview = QLabel(
            "PREVIEW PAGE · Synthetic examples; Cases, Overview, Evidence intake, Artifacts, Activity, and Findings use real records"
        )
        preview.setObjectName("previewBanner")
        preview.setWordWrap(True)
        workspace_layout.addWidget(preview)
        self.pages = QStackedWidget(self.workspace)
        self.evidence_page = EvidencePage(self.pages)
        self.cases_page = CasesPage(self.pages)
        self.overview_page = OverviewPage(self.pages)
        self.activity_page = ActivityPage(self.pages)
        self.findings_page = FindingsPage(self.pages)
        self.artifacts_page = ArtifactsPage(self.pages)
        self.graph_page = InvestigationGraphPage(self.pages)
        self.findings_page.graph_requested.connect(self._show_finding_graph)
        self.reports_page = ReportsPage(self.pages)
        functional = {
            "Cases": self.cases_page,
            "Overview": self.overview_page,
            "Evidence & Analysis": self.evidence_page,
            "Artifacts": self.artifacts_page,
            "Reports": self.reports_page,
            "Activity": self.activity_page,
            "Findings": self.findings_page,
            "Investigation Graph": self.graph_page,
        }
        for name in self.PAGE_NAMES:
            self.pages.addWidget(
                functional[name] if name in functional else PLACEHOLDER_PAGES[name]()
            )
        workspace_layout.addWidget(self.pages, 1)
        status = QLabel("Idle  ·  No active job")
        self.job_status = status
        status.setObjectName("jobStatus")
        self.evidence_page.status_changed.connect(status.setText)
        self.pages.currentChanged.connect(lambda index: preview.setVisible(index in (6, 8, 9)))
        self.pages.currentChanged.connect(self._page_changed)
        preview.hide()
        self.cases_page.case_opened.connect(self._open_case)
        self.overview_page.case_opened.connect(self._open_case)
        self.overview_page.cases_requested.connect(lambda: self.sidebar.setCurrentRow(0))
        self.overview_page.import_requested.connect(self._add_case_evidence)
        self.overview_page.analyze_requested.connect(self._start_analysis)
        self.evidence_page.evidence_registered.connect(self._evidence_registered)
        self.evidence_page.analyze_requested.connect(self._analyze_registered_evidence)
        self.evidence_page.intake_progress.connect(self._intake_progress)
        self.evidence_page.intake_finished.connect(self.overview_page.finish_intake_progress)
        self.evidence_page.intake_failed.connect(self.overview_page.show_intake_failure)
        workspace_layout.addWidget(status)
        layout.addWidget(self.workspace, 1)
        app = QApplication.instance()
        assert isinstance(app, QApplication)
        app.paletteChanged.connect(self._apply_theme)
        self._apply_theme()

        self.sidebar.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.sidebar.setCurrentRow(0)
        self.setCentralWidget(container)
        self._interactive_cursors = InteractiveCursors(self)
        self.analysis_timer = QTimer(self)
        self.analysis_timer.setInterval(500)
        self.analysis_timer.timeout.connect(self._analysis_progress)

    def _analyze_registered_evidence(self, result: IntakeResult) -> None:
        if self.analysis_worker is not None or self.evidence_page.busy:
            QMessageBox.information(self, "Job in progress", "Wait for the current job to finish.")
            return
        try:
            case = CaseRepository(Database(result.database_path)).get_by_id(result.evidence.case_id)
            if case is None:
                raise ValueError("The evidence case is no longer available.")
            self._open_case(str(result.database_path.parent), case)
            choice = self.overview_page.evidence_choice
            for index in range(choice.count()):
                if choice.itemData(index).id == result.evidence.id:
                    choice.setCurrentIndex(index)
                    break
            else:
                raise ValueError("The registered evidence is no longer available.")
            if not self.overview_page.analyze_button.isEnabled():
                raise ValueError("Analysis requires an open case and verified evidence.")
        except Exception as exc:
            QMessageBox.warning(self, "Cannot analyze evidence", str(exc))
            return
        self._start_analysis()

    def _start_analysis(self) -> None:
        if self.analysis_worker is not None or self.evidence_page.busy:
            QMessageBox.information(self, "Job in progress", "Wait for the current job to finish.")
            return
        evidence = self.overview_page.evidence_choice.currentData()
        if evidence is None:
            return
        dialog = AnalysisDialog(self.overview_page.workspace_path, evidence, self.workspace)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            dialog.deleteLater()
            return
        request = dialog.request
        dialog.deleteLater()
        self.analysis_run = None
        if request is None:
            return
        self.analysis_worker = AnalysisWorker(request, self)
        self.analysis_worker.started_run.connect(self._analysis_started)
        self.analysis_worker.succeeded.connect(self._analysis_succeeded)
        self.analysis_worker.failed.connect(self._analysis_failed)
        self.analysis_worker.finished.connect(self._analysis_finished)
        self.overview_page.analysis_busy = True
        self.overview_page.analyze_button.setEnabled(False)
        self.evidence_page.form.setEnabled(False)
        self.evidence_page.start.setEnabled(False)
        self.evidence_page.analyse.setEnabled(False)
        self.job_status.setText("Preparing analysis · validating plugins, symbols, and rules")
        self.analysis_worker.start()
        self.analysis_timer.start()

    def _analysis_started(self, run: AnalysisRun) -> None:
        self.analysis_run = run
        self.overview_page.refresh()

    def _analysis_progress(self) -> None:
        if self.analysis_worker is None or self.analysis_run is None:
            return
        try:
            database = Database(Path(self.analysis_worker.request.workspace) / "memsentry.sqlite3",
                                timeout_seconds=0.1)
            events = WorkflowRepository(database).list_events(self.analysis_run.evidence_id, self.analysis_run.id)
            if events:
                event = events[-1]
                self.job_status.setText(f"Analysis · {event['phase']} · {event['status']} · "
                                       f"{event['progress']}% · {event['message']}")
        except Exception:
            # A brief database lock must not interrupt the running forensic job.
            pass

    def _analysis_succeeded(self, run: AnalysisRun) -> None:
        self.analysis_timer.stop()
        self.job_status.setText(f"Analysis {run.status} · {run.id}")
        self.overview_page.refresh()
        self.findings_page.refresh()
        self.graph_page.refresh()
        if run.error_message:
            self.overview_page.error.setText(run.error_message)

    def _analysis_failed(self, message: str) -> None:
        self.analysis_timer.stop()
        self.job_status.setText(f"Analysis failed · {message}")
        self.overview_page.refresh()
        self.overview_page.error.setText(f"Analysis failed: {message}")

    def _analysis_finished(self) -> None:
        self.analysis_timer.stop()
        if self.analysis_worker is not None:
            self.analysis_worker.deleteLater()
        self.analysis_worker = None
        self.overview_page.analysis_busy = False
        self.overview_page._evidence_changed()
        self.evidence_page.form.setEnabled(True)
        self.evidence_page.start.setEnabled(True)
        self.evidence_page.analyse.setEnabled(self.evidence_page.registered_result is not None)

    def _open_case(self, workspace: str, case: Case) -> None:
        if not self.graph_page.open_case(workspace, case):
            return
        self.overview_page.open_case(workspace, case)
        self.activity_page.open_case(workspace, case)
        self.artifacts_page.open_case(workspace, case)
        self.findings_page.open_case(workspace, case)
        self.reports_page.open_case(workspace, case)
        self.sidebar.setCurrentRow(1)

    def _show_finding_graph(self, run_id, finding_id) -> None:
        self.graph_page.refresh()
        index = self.graph_page.run_choice.findData(str(run_id))
        if index >= 0:
            self.graph_page.run_choice.setCurrentIndex(index)
            if self.graph_page.run_choice.currentData() != str(run_id):
                return
            key = str(finding_id)
            self.graph_page.visible = self.graph_page.graph.neighborhood({key})
            self.graph_page.render_graph()
            self.graph_page.capture_edit()
            if key in self.graph_page.node_items:
                self.graph_page.node_items[key].setSelected(True)
            self.sidebar.setCurrentRow(5)

    def _page_changed(self, index: int) -> None:
        if index == 3:  # Artifacts page index
            self.artifacts_page.refresh()
        elif index == 7:  # Activity page index
            self.activity_page.refresh()
        elif index == 4:
            self.findings_page.refresh()

    def _intake_progress(self, message: str, value: int) -> None:
        overview = self.overview_page
        case = overview.case
        if (case and case.case_number == self.evidence_page.case_number.text().strip()
                and Path(overview.workspace_path).resolve() ==
                Path(self.evidence_page.workspace.text()).expanduser().resolve()):
            overview.show_intake_progress(message, value)

    def _add_case_evidence(self) -> None:
        if self.analysis_worker is not None:
            QMessageBox.information(self, "Analysis is running", "Wait for analysis to finish before adding evidence.")
            return
        if self.evidence_page.busy:
            QMessageBox.information(self, "Intake is running",
                                    "Wait for the current intake to finish before changing cases.")
            self.sidebar.setCurrentRow(2)
            return
        case = self.overview_page.case
        if case and case.status == "open":
            if self.evidence_page.use_case(self.overview_page.workspace_path, case):
                self.sidebar.setCurrentRow(2)
            else:
                QMessageBox.warning(self, "Case unavailable", self.evidence_page.result.toPlainText())

    def _evidence_registered(self, result: IntakeResult) -> None:
        try:
            workspace = str(result.database_path.parent)
            case = CaseRepository(Database(result.database_path)).get_by_id(result.evidence.case_id)
            self.cases_page.workspace.setText(workspace)
            self.cases_page.refresh()
            if case:
                self.overview_page.open_case(workspace, case)
        except Exception as exc:
            self.overview_page.error.setText(f"Evidence saved; overview could not refresh: {exc}")

    def _apply_theme(self) -> None:
        self.workspace.setStyleSheet(workspace_stylesheet())

    def closeEvent(self, event: QCloseEvent) -> None:
        if self.analysis_worker is not None:
            QMessageBox.information(self, "Analysis is running",
                                    "Wait for analysis and its final SHA-256 check before closing.")
            event.ignore()
            return
        if self.evidence_page.busy:
            QMessageBox.information(
                self,
                "Evidence intake is running",
                "Cancel the intake and wait for it to stop before closing.",
            )
            event.ignore()
            return
        if not self.graph_page.confirm_discard():
            event.ignore()
            return
        super().closeEvent(event)
