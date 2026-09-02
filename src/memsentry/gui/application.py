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


class MainWindow(QMainWindow):
    def __init__(self) -> None:
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

        self.pages.addWidget(self.create_page("Cases"))
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

    def create_page(self, title: str) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)

        label = QLabel(f"{title} View")
        layout.addWidget(label)

        return page


def create_application() -> QApplication:
    app = QApplication([])

    window = MainWindow()
    window.show()

    # Keep a reference to the window
    app.main_window = window  # type: ignore[attr-defined]

    return app
