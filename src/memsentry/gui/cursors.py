"""Consistent cursors for actionable controls in the application window."""

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtWidgets import QAbstractButton, QApplication, QComboBox, QWidget


class InteractiveCursors(QObject):
    """Include dynamically created controls and track their enabled state."""

    def __init__(self, window: QWidget) -> None:
        super().__init__(window)
        self.window = window
        app = QApplication.instance()
        assert isinstance(app, QApplication)
        app.installEventFilter(self)
        for widget in window.findChildren(QWidget):
            self._update(widget)

    def _update(self, widget: QObject) -> None:
        if not isinstance(widget, (QAbstractButton, QComboBox)):
            return
        # Follow QObject ownership across dialog window boundaries as well.
        owner = widget.parent()
        while owner is not None and owner is not self.window:
            owner = owner.parent()
        if owner is self.window:
            widget.setCursor(
                Qt.CursorShape.PointingHandCursor
                if widget.isEnabled()
                else Qt.CursorShape.ArrowCursor
            )

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if event.type() in (QEvent.Type.Polish, QEvent.Type.EnabledChange, QEvent.Type.Show):
            self._update(watched)
        return False
