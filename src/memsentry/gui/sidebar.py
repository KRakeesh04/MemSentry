"""Sidebar navigation with system-aware light and dark styling."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QPalette
from PySide6.QtWidgets import (
    QApplication,
    QButtonGroup,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from memsentry.gui.branding import BrandWidget


class Sidebar(QWidget):
    currentRowChanged = Signal(int)

    def __init__(self, page_names: tuple[str, ...], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("sidebar")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setAccessibleName("Page navigation")
        self.setMinimumWidth(232)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 24, 16, 16)
        layout.setSpacing(8)

        layout.addWidget(BrandWidget(self))
        layout.addSpacing(16)

        scroll = QScrollArea(self)
        scroll.setWidgetResizable(True)
        navigation = QWidget(scroll)
        navigation_layout = QVBoxLayout(navigation)
        navigation_layout.setContentsMargins(0, 0, 0, 0)
        navigation_layout.setSpacing(8)
        scroll.setWidget(navigation)
        layout.addWidget(scroll, 1)

        self.buttons = QButtonGroup(self)
        self.buttons.setExclusive(True)
        for index, name in enumerate(page_names):
            button = QPushButton(name.replace("&", "&&"), self)
            button.setCheckable(True)
            button.setAccessibleName(name)
            button.setMinimumHeight(40)
            self.buttons.addButton(button, index)
            if name in ("Settings", "Help"):
                layout.addWidget(button)
            else:
                navigation_layout.addWidget(button)
        navigation_layout.addStretch()
        self.buttons.idClicked.connect(self.setCurrentRow)
        app = QApplication.instance()
        assert isinstance(app, QApplication)
        app.paletteChanged.connect(self._apply_theme)
        self._apply_theme()

    def setCurrentRow(self, index: int) -> None:
        button = self.buttons.button(index)
        if button is not None:
            button.setChecked(True)
            self.currentRowChanged.emit(index)

    def _apply_theme(self) -> None:
        dark = QApplication.palette().color(QPalette.ColorRole.Window).lightness() < 128
        background, text, border, hover, selected, accent = (
            ("#171B22", "#E5E7EB", "#303641", "#252C36", "#20334F", "#60A5FA")
            if dark
            else ("#F8FAFC", "#334155", "#E2E8F0", "#EEF2F6", "#E8F0FE", "#2563EB")
        )
        self.setStyleSheet(f"""
            QWidget#sidebar {{ background: {background}; border-right: 1px solid {border}; }}
            QScrollArea, QScrollArea > QWidget, QScrollArea > QWidget > QWidget {{
                background: {background}; border: none;
            }}
            QPushButton {{
                color: {text}; background: transparent; text-align: left;
                padding: 8px 12px; border: 1px solid transparent;
                border-left: 3px solid transparent; border-radius: 6px;
            }}
            QPushButton:hover {{ background: {hover}; }}
            QPushButton:checked {{
                color: {accent}; background: {selected};
                border-left: 3px solid {accent}; font-weight: bold;
            }}
            QPushButton:focus {{ border: 1px solid {accent}; border-left: 3px solid {accent}; }}
        """)
