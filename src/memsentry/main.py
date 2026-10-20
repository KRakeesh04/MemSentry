"""Desktop application entry point."""

import sys

from PySide6.QtWidgets import QApplication, QMessageBox

from memsentry.app.bootstrap import configure_portable_settings, load_portable_configuration
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
    try:
        load_portable_configuration()
        configure_portable_settings()
    except (OSError, ValueError) as exc:
        QMessageBox.critical(None, "Configuration could not be loaded", str(exc))
        return
    apply_saved_theme(application)
    window = MainWindow()
    window.show()
    sys.exit(application.exec())
