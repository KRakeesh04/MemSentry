"""Shared MemSentry icon and wordmark for application surfaces."""

from pathlib import Path

from PySide6.QtGui import QFont, QIcon, QPalette
from PySide6.QtSvgWidgets import QSvgWidget
from PySide6.QtWidgets import QApplication, QHBoxLayout, QLabel, QWidget

LOGO_PATH = Path(__file__).resolve().parent / "assets" / "shield.svg"


def application_icon() -> QIcon:
    """Return the shared scalable shield icon."""
    return QIcon(str(LOGO_PATH))


class BrandWidget(QWidget):
    """Shield and two-tone wordmark, styled for the current application palette."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAccessibleName("MemSentry")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(12)
        logo = QSvgWidget(str(LOGO_PATH), self)
        logo.setFixedSize(36, 40)
        layout.addWidget(logo)
        self.wordmark = QLabel(self)
        font = self.wordmark.font()
        font.setPointSize(11)
        font.setBold(True)
        font.setLetterSpacing(QFont.SpacingType.AbsoluteSpacing, 1.0)
        self.wordmark.setFont(font)
        layout.addWidget(self.wordmark)
        layout.addStretch()
        app = QApplication.instance()
        assert isinstance(app, QApplication)
        app.paletteChanged.connect(self._apply_theme)
        self._apply_theme()

    def _apply_theme(self) -> None:
        dark = QApplication.palette().color(QPalette.ColorRole.Window).lightness() < 128
        text, accent = ("#E5E7EB", "#60A5FA") if dark else ("#334155", "#2563EB")
        self.wordmark.setText(
            f'<span style="color:{text}">MEM</span>'
            f'<span style="color:{accent}">SENTRY</span>'
        )
