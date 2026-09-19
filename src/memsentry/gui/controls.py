"""Shared controls that use the workspace theme instead of native menu painting."""

from PySide6.QtWidgets import QComboBox, QListView, QStyledItemDelegate, QWidget


class ThemedComboBox(QComboBox):
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        view = QListView(self)
        self.setView(view)
        # Native combo menu delegates can paint the desktop menu background over QSS.
        view.setItemDelegate(QStyledItemDelegate(view))
