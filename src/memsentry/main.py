"""Desktop application entry point."""

import sys

from PySide6.QtWidgets import QApplication

from memsentry.gui.branding import application_icon
from memsentry.gui.main_window import MainWindow


def main() -> None:
    application = QApplication(sys.argv)
    application.setApplicationName("MemSentry")
    application.setWindowIcon(application_icon())
    window = MainWindow()
    window.show()
    sys.exit(application.exec())
