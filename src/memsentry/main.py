"""Desktop application entry point."""

import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from memsentry.app.bootstrap import load_portable_configuration
from memsentry.gui.branding import application_icon
from memsentry.gui.main_window import MainWindow
from memsentry.gui.theme import apply_saved_theme


def main() -> None:
    if sys.platform == "win32":
        import ctypes

        # Keep the taskbar identity tied to MemSentry rather than the Python interpreter.
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("MemSentry.Desktop")
    application = QApplication(sys.argv)
    application.setApplicationName("MemSentry")
    application.setDesktopFileName("memsentry")
    application.setWindowIcon(application_icon())
    apply_saved_theme(application)
    try:
        load_portable_configuration()
    except (OSError, ValueError) as exc:
        QMessageBox.critical(None, "Configuration could not be loaded", str(exc))
        return
    window = MainWindow()
    window.show()
    sys.exit(application.exec())
