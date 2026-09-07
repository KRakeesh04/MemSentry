"""Main PySide6 application window and navigation container for MemSentry."""

from typing import cast

from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from memsentry.analysis.orchestrator import AnalysisOrchestrator
from memsentry.gui.analysis_view import AnalysisView
from memsentry.gui.cases_view import CasesView
from memsentry.gui.evidence_view import EvidenceView
from memsentry.models.case import Case
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.case_repository import CaseRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository


class MainWindow(QMainWindow):
    """Main application window container for MemSentry."""

    def __init__(
        self,
        case_repository: CaseRepository,
        evidence_repository: EvidenceRepository,
        analysis_run_repository: AnalysisRunRepository,
        plugin_run_repository: PluginRunRepository,
        analysis_orchestrator: AnalysisOrchestrator | None = None,
    ) -> None:
        super().__init__()
        self.case_repository = case_repository
        self.evidence_repository = evidence_repository
        self.analysis_run_repository = analysis_run_repository
        self.plugin_run_repository = plugin_run_repository
        self.analysis_orchestrator = analysis_orchestrator
        self.active_case: object | None = None

        self.setWindowTitle("MemSentry")
        self.resize(1200, 800)

        # Main container
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        # Main horizontal layout
        main_layout = QHBoxLayout(central_widget)

        # Navigation sidebar
        self.navigation = QListWidget()
        self.navigation.addItems(
            [
                "Cases",
                "Evidence",
                "Analysis",
                "Dashboard",
                "Processes",
                "Reports",
            ]
        )

        # Pages
        self.pages = QStackedWidget()

        self.cases_view = CasesView(case_repository)
        self.cases_view.case_opened.connect(self.open_case)
        self.pages.addWidget(self.cases_view)

        self.evidence_view = EvidenceView(evidence_repository)
        self.pages.addWidget(self.evidence_view)

        self.analysis_view = AnalysisView(
            evidence_repository=evidence_repository,
            analysis_run_repository=analysis_run_repository,
            plugin_run_repository=plugin_run_repository,
            analysis_orchestrator=analysis_orchestrator,
        )
        self.pages.addWidget(self.analysis_view)

        self.evidence_view.evidence_created.connect(
            lambda _: self.analysis_view.load_evidence_for_case()
        )

        self.pages.addWidget(self.create_page("Dashboard"))
        self.pages.addWidget(self.create_page("Processes"))
        self.pages.addWidget(self.create_page("Reports"))

        # Add sidebar and pages to main layout
        main_layout.addWidget(self.navigation)
        main_layout.addWidget(self.pages)

        # Connect navigation to pages
        self.navigation.currentRowChanged.connect(self.pages.setCurrentIndex)

        # Start with Cases page
        self.navigation.setCurrentRow(0)

    def open_case(self, case: object) -> None:
        """Keep the opened case available, propagate to EvidenceView and AnalysisView, and switch page."""
        self.active_case = case
        if isinstance(case, Case):
            self.evidence_view.set_active_case(case)
            self.analysis_view.set_active_case(case)
        else:
            self.evidence_view.set_active_case(None)
            self.analysis_view.set_active_case(None)
        self.navigation.setCurrentRow(1)

    def create_page(self, title: str) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        label = QLabel(f"{title} View")
        layout.addWidget(label)

        return page


def create_application(
    case_repository: CaseRepository,
    evidence_repository: EvidenceRepository,
    analysis_run_repository: AnalysisRunRepository,
    plugin_run_repository: PluginRunRepository,
    analysis_orchestrator: AnalysisOrchestrator | None = None,
) -> QApplication:
    """Instantiate application and main window with injected repositories and orchestrator."""
    app = cast(QApplication, QApplication.instance() or QApplication([]))

    window = MainWindow(
        case_repository,
        evidence_repository,
        analysis_run_repository,
        plugin_run_repository,
        analysis_orchestrator,
    )
    window.show()

    # Keep a reference to the window
    app.main_window = window  # type: ignore[attr-defined]

    return app
