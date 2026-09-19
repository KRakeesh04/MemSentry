"""Minimal application shell and sidebar navigation."""

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
from memsentry.gui.pages import PLACEHOLDER_PAGES
from memsentry.gui.pages.evidence import EvidencePage
from memsentry.gui.sidebar import Sidebar
from memsentry.gui.theme import workspace_stylesheet


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
            "PREVIEW PAGES  ·  Synthetic examples; use Evidence & Analysis for real intake"
        )
        preview.setObjectName("previewBanner")
        preview.setWordWrap(True)
        workspace_layout.addWidget(preview)
        self.pages = QStackedWidget(self.workspace)
        self.evidence_page = EvidencePage(self.pages)
        for name in self.PAGE_NAMES:
            self.pages.addWidget(
                self.evidence_page if name == "Evidence & Analysis" else PLACEHOLDER_PAGES[name]()
            )
        workspace_layout.addWidget(self.pages, 1)
        status = QLabel("Idle  ·  No active job")
        status.setObjectName("jobStatus")
        self.evidence_page.status_changed.connect(status.setText)
        self.pages.currentChanged.connect(lambda index: preview.setVisible(index != 2))
        workspace_layout.addWidget(status)
        layout.addWidget(self.workspace, 1)
        QApplication.instance().paletteChanged.connect(self._apply_theme)
        self._apply_theme()

        self.sidebar.currentRowChanged.connect(self.pages.setCurrentIndex)
        self.sidebar.setCurrentRow(0)
        self.setCentralWidget(container)

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
