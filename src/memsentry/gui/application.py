"""Main PySide6 application shell container for MemSentry DFIR Investigation Suite."""

from __future__ import annotations

from typing import cast

from PySide6.QtWidgets import (
    QApplication,
    QHBoxLayout,
    QMainWindow,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

from memsentry.analysis.orchestrator import AnalysisOrchestrator
from memsentry.app.artifact_service import ArtifactService
from memsentry.gui.acquisition_view import EvidenceAcquisitionView
from memsentry.gui.analysis_view import AnalysisView
from memsentry.gui.cases_view import CasesView
from memsentry.gui.components import SidebarWidget, TopHeader
from memsentry.gui.dashboard_view import DashboardView
from memsentry.gui.evidence_view import EvidenceView
from memsentry.gui.findings_view import FindingsView
from memsentry.gui.graph_view import RelationshipGraphView
from memsentry.gui.reports_view import ReportBuilderView
from memsentry.gui.theme import MEMSENTRY_QSS
from memsentry.gui.timeline_view import TimelineView
from memsentry.models.case import Case
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.artifact_repository import ArtifactRepository
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
        artifact_repository: ArtifactRepository | None = None,
        artifact_service: ArtifactService | None = None,
    ) -> None:
        super().__init__()
        self.case_repository = case_repository
        self.evidence_repository = evidence_repository
        self.analysis_run_repository = analysis_run_repository
        self.plugin_run_repository = plugin_run_repository
        self.analysis_orchestrator = analysis_orchestrator
        self.artifact_repository = artifact_repository

        self.artifact_service: ArtifactService | None = None
        if artifact_service is not None:
            self.artifact_service = artifact_service
        elif artifact_repository is not None:
            self.artifact_service = ArtifactService(
                artifact_repository=artifact_repository,
                analysis_run_repository=analysis_run_repository,
            )

        self.active_case: object | None = None

        self.setWindowTitle("MemSentry")
        self.resize(1380, 880)
        self.setStyleSheet(MEMSENTRY_QSS)

        # Central Widget & Main Horizon Layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)

        main_layout = QHBoxLayout(central_widget)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Sidebar Navigation Component
        self.sidebar = SidebarWidget()
        self.navigation = self.sidebar.nav_list  # Alias for backward compatibility with tests
        main_layout.addWidget(self.sidebar)

        # Right Content Container
        right_container = QWidget()
        right_layout = QVBoxLayout(right_container)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(0)

        # Top Header Component
        self.header = TopHeader()
        self.header.create_case_requested.connect(self._on_header_create_case)
        self.header.add_evidence_requested.connect(self._on_header_add_evidence)
        right_layout.addWidget(self.header)

        # Pages Stack Widget (8 Navigable Pages)
        self.pages = QStackedWidget()

        # 0. Command Center / Dashboard
        self.dashboard_view = DashboardView(artifact_service=self.artifact_service)
        self.dashboard_view.open_investigation_requested.connect(lambda: self.sidebar.nav_list.setCurrentRow(1))
        self.dashboard_view.view_all_findings_requested.connect(lambda: self.sidebar.nav_list.setCurrentRow(4))
        self.pages.addWidget(self.dashboard_view)

        # 1. Evidence Acquisition (Icon ⤓)
        self.acquisition_view = EvidenceAcquisitionView(evidence_repository)
        self.pages.addWidget(self.acquisition_view)

        # 2. Evidence Explorer (Icon 🔍)
        self.evidence_view = EvidenceView(
            evidence_repository=evidence_repository,
            artifact_service=self.artifact_service,
            analysis_run_repository=analysis_run_repository,
        )
        self.pages.addWidget(self.evidence_view)

        # 3. Analysis / Plugin Center (Icon ⚡)
        self.analysis_view = AnalysisView(
            evidence_repository=evidence_repository,
            analysis_run_repository=analysis_run_repository,
            plugin_run_repository=plugin_run_repository,
            analysis_orchestrator=analysis_orchestrator,
        )
        self.analysis_view.open_evidence_explorer_requested.connect(
            lambda: self.sidebar.nav_list.setCurrentRow(2)
        )
        self.pages.addWidget(self.analysis_view)

        # Wire acquisition and evidence signals to analysis and graph views
        self.acquisition_view.evidence_created.connect(self._on_evidence_registered)
        self.evidence_view.evidence_created.connect(
            lambda _: self.analysis_view.load_evidence_for_case()
        )
        self.evidence_view.open_relationship_graph_requested.connect(
            lambda: self.sidebar.nav_list.setCurrentRow(6)
        )

        # 4. Findings Dashboard (Icon ⚠️)
        self.findings_view = FindingsView()
        self.findings_view.open_relationship_graph_requested.connect(
            lambda: self.sidebar.nav_list.setCurrentRow(6)
        )
        self.findings_view.open_evidence_explorer_requested.connect(
            lambda: self.sidebar.nav_list.setCurrentRow(2)
        )
        self.pages.addWidget(self.findings_view)

        # 5. Investigation Timeline (Icon 🕒)
        self.timeline_view = TimelineView()
        self.timeline_view.open_relationship_graph_requested.connect(
            lambda: self.sidebar.nav_list.setCurrentRow(6)
        )
        self.timeline_view.open_evidence_explorer_requested.connect(
            lambda: self.sidebar.nav_list.setCurrentRow(2)
        )
        self.pages.addWidget(self.timeline_view)

        # 6. Relationship Graph (Icon ☊)
        self.graph_view = RelationshipGraphView()
        self.graph_view.back_to_investigation_requested.connect(
            lambda: self.sidebar.nav_list.setCurrentRow(2)
        )
        self.graph_view.view_in_process_tree_requested.connect(
            lambda: self.sidebar.nav_list.setCurrentRow(2)
        )
        self.graph_view.show_in_timeline_requested.connect(
            lambda: self.sidebar.nav_list.setCurrentRow(5)
        )
        self.graph_view.check_findings_requested.connect(
            lambda: self.sidebar.nav_list.setCurrentRow(4)
        )
        self.pages.addWidget(self.graph_view)

        # 7. Report Builder (Icon 📄)
        self.reports_view = ReportBuilderView()
        self.pages.addWidget(self.reports_view)

        # Standalone Cases View modal handler
        self.cases_view = CasesView(case_repository)
        self.cases_view.case_opened.connect(self.open_case)

        right_layout.addWidget(self.pages, stretch=1)
        main_layout.addWidget(right_container, stretch=1)

        # Connect Sidebar selection to Pages Stack
        self.sidebar.navigation_changed.connect(self._on_nav_changed)

        # Initial Page: Command Center
        self.sidebar.nav_list.setCurrentRow(0)

    def _on_nav_changed(self, index: int) -> None:
        if 0 <= index < self.pages.count():
            self.pages.setCurrentIndex(index)
            titles = [
                ("Command Center", "DFIR Memory Investigation & Triage Overview"),
                ("Evidence Acquisition", "Add Evidence to Investigation"),
                ("Evidence Explorer", "Manage RAM evidence files and view applicable forensic plugins"),
                ("Analysis & Plugin Center", "Configure Volatility 3 plugins and track analysis run progress"),
                ("Findings Dashboard", "Memory process triage findings, threat indicators, and risk scores"),
                ("Investigation Timeline", "Chronological sequence of process execution and network events"),
                ("Relationship Graph", "Visual tree of parent-child processes, injected memory, and sockets"),
                ("Report Builder", "Generate, verify hash integrity, and export standardized DFIR reports"),
            ]
            if index < len(titles):
                title, subtitle = titles[index]
                self.header.set_title_and_subtitle(title, subtitle)

    def open_case(self, case: object) -> None:
        """Keep the opened case available, propagate to views, and switch page."""
        self.active_case = case
        if isinstance(case, Case):
            self.acquisition_view.set_active_case(case)
            self.evidence_view.set_active_case(case)
            self.analysis_view.set_active_case(case)
            self.dashboard_view.set_active_case(case)
            self.sidebar.set_active_case_display(
                case.name, status_str=case.status.value.upper()
            )
        else:
            self.acquisition_view.set_active_case(None)
            self.evidence_view.set_active_case(None)
            self.analysis_view.set_active_case(None)
            self.dashboard_view.set_active_case(None)
            self.sidebar.set_active_case_display(None, "IDLE")

        self.navigation.setCurrentRow(1)

    def _on_evidence_registered(self, evidence: object) -> None:
        self.analysis_view.load_evidence_for_case()
        self.evidence_view.load_evidence()

    def _on_header_create_case(self) -> None:
        self.cases_view.open_create_dialog()

    def _on_header_add_evidence(self) -> None:
        self.sidebar.nav_list.setCurrentRow(1)


def create_application(
    case_repository: CaseRepository,
    evidence_repository: EvidenceRepository,
    analysis_run_repository: AnalysisRunRepository,
    plugin_run_repository: PluginRunRepository,
    analysis_orchestrator: AnalysisOrchestrator | None = None,
    artifact_repository: ArtifactRepository | None = None,
    artifact_service: ArtifactService | None = None,
) -> QApplication:
    """Instantiate application and main window with injected repositories and orchestrator."""
    app = cast(QApplication, QApplication.instance() or QApplication([]))

    window = MainWindow(
        case_repository,
        evidence_repository,
        analysis_run_repository,
        plugin_run_repository,
        analysis_orchestrator,
        artifact_repository=artifact_repository,
        artifact_service=artifact_service,
    )
    window.show()

    # Keep a reference to the window
    app.main_window = window  # type: ignore[attr-defined]

    return app
