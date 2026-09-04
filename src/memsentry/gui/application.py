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

from memsentry.gui.cases_view import CasesView
from memsentry.storage.repositories.case_repository import CaseRepository


class MainWindow(QMainWindow):
    def __init__(self, case_repository: CaseRepository) -> None:
        super().__init__()

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
        self.pages.addWidget(self.create_page("Evidence"))
        self.pages.addWidget(self.create_page("Analysis"))
        self.pages.addWidget(self.create_page("Dashboard"))
        self.pages.addWidget(self.create_page("Processes"))
        self.pages.addWidget(self.create_page("Reports"))

        # Add sidebar and pages to main layout
        main_layout.addWidget(self.navigation)
        main_layout.addWidget(self.pages)

        # Connect navigation to pages
        self.navigation.currentRowChanged.connect(
            self.pages.setCurrentIndex
        )

        # Start with Cases page
        self.navigation.setCurrentRow(0)

    def open_case(self, case: object) -> None:
        """Keep the opened case available and move to the existing Evidence page."""
        self.active_case = case
        self.navigation.setCurrentRow(1)

    def create_page(self, title: str) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        label = QLabel(f"{title} View")
        layout.addWidget(label)

        return page


def create_application(case_repository: CaseRepository) -> QApplication:
    app = QApplication([])

    window = MainWindow(case_repository)
    window.show()

    # Keep a reference to the window
    app.main_window = window  # type: ignore[attr-defined]

    return app
