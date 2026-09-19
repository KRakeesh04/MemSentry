"""Desktop application entry point."""

import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from memsentry.app.bootstrap import load_portable_configuration
from memsentry.gui.branding import application_icon
from memsentry.gui.main_window import MainWindow


def main() -> None:
    application = QApplication(sys.argv)
    application.setApplicationName("MemSentry")
    application.setWindowIcon(application_icon())
    try:
        load_portable_configuration()
    except (OSError, ValueError) as exc:
        QMessageBox.critical(None, "Configuration could not be loaded", str(exc))
        return
    window = MainWindow()
    window.show()
    sys.exit(application.exec())
