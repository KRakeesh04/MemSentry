"""Minimal application shell and sidebar navigation."""

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QMessageBox,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from memsentry.gui.branding import application_icon
from memsentry.gui.cursors import InteractiveCursors
from memsentry.gui.pages import PLACEHOLDER_PAGES
from memsentry.gui.pages.cases import CasesPage
from memsentry.gui.pages.evidence import EvidencePage
from memsentry.gui.pages.overview import OverviewPage
from memsentry.gui.sidebar import Sidebar
from memsentry.gui.theme import workspace_stylesheet
from memsentry.storage.database import Database
from memsentry.storage.repositories.case_repository import CaseRepository


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
            "PREVIEW PAGE · Synthetic examples; Cases, Overview, and Evidence intake use real records"
        )
        preview.setObjectName("previewBanner")
        preview.setWordWrap(True)
        workspace_layout.addWidget(preview)
        self.pages = QStackedWidget(self.workspace)
        self.evidence_page = EvidencePage(self.pages)
        self.cases_page = CasesPage(self.pages)
        self.overview_page = OverviewPage(self.pages)
        functional = {"Cases": self.cases_page, "Overview": self.overview_page,
                      "Evidence & Analysis": self.evidence_page}
        for name in self.PAGE_NAMES:
            self.pages.addWidget(
                functional[name] if name in functional else PLACEHOLDER_PAGES[name]()
            )
        workspace_layout.addWidget(self.pages, 1)
        status = QLabel("Idle  ·  No active job")
        status.setObjectName("jobStatus")
        self.evidence_page.status_changed.connect(status.setText)
        self.pages.currentChanged.connect(lambda index: preview.setVisible(index > 2))
        preview.hide()
        self.cases_page.case_opened.connect(self._open_case)
        self.overview_page.case_opened.connect(self._open_case)
        self.overview_page.cases_requested.connect(lambda: self.sidebar.setCurrentRow(0))
        self.overview_page.import_requested.connect(self._add_case_evidence)
        self.evidence_page.evidence_registered.connect(self._evidence_registered)
        self.evidence_page.intake_progress.connect(self._intake_progress)
        self.evidence_page.intake_finished.connect(self.overview_page.finish_intake_progress)
        self.evidence_page.intake_failed.connect(self.overview_page.show_intake_failure)
        workspace_layout.addWidget(status)
        layout.addWidget(self.workspace, 1)
        QApplication.instance().paletteChanged.connect(self._apply_theme)
        self._apply_theme()

        self.sidebar.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.sidebar.setCurrentRow(0)
        self.setCentralWidget(container)
        self._interactive_cursors = InteractiveCursors(self)

    def _open_case(self, workspace, case):
        self.overview_page.open_case(workspace, case)
        self.sidebar.setCurrentRow(1)

    def _intake_progress(self, message, value):
        overview = self.overview_page
        case = overview.case
        if (case and case.case_number == self.evidence_page.case_number.text().strip()
                and Path(overview.workspace_path).resolve() ==
                Path(self.evidence_page.workspace.text()).expanduser().resolve()):
            overview.show_intake_progress(message, value)

    def _add_case_evidence(self):
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

    def _evidence_registered(self, result):
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

    def closeEvent(self, event) -> None:
        if self.evidence_page.busy:
            QMessageBox.information(
                self,
                "Evidence intake is running",
                "Cancel the intake and wait for it to stop before closing.",
            )
            event.ignore()
            return
        super().closeEvent(event)
