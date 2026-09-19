"""Consistent cursors for actionable controls in the application window."""

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import QAbstractButton, QApplication, QComboBox, QWidget


class InteractiveCursors(QObject):
    """Include dynamically created controls and track their enabled state."""

    def __init__(self, window: QWidget) -> None:
        super().__init__(window)
        self.window = window
        QApplication.instance().installEventFilter(self)
        for widget in window.findChildren(QWidget):
            self._update(widget)

    def _update(self, widget: QObject) -> None:
        if isinstance(widget, (QAbstractButton, QComboBox)) and self.window.isAncestorOf(widget):
            widget.setCursor(
                Qt.CursorShape.PointingHandCursor
                if widget.isEnabled()
                else Qt.CursorShape.ArrowCursor
            )

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if event.type() in (QEvent.Type.Polish, QEvent.Type.EnabledChange, QEvent.Type.Show):
            self._update(watched)
        return False
