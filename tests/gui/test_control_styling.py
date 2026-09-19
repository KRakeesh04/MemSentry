import pytest
from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import (
    QAbstractItemView,
    QStyledItemDelegate,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from memsentry.gui.controls import ThemedComboBox
from memsentry.gui.theme import workspace_stylesheet


@pytest.mark.parametrize("dark", [False, True])
def test_popup_background_and_keyboard_selection(qtbot, qapp, tmp_path, dark):
    original = qapp.palette()
    palette = QPalette(original)
    palette.setColor(QPalette.ColorRole.Window, QColor("#11151C" if dark else "#F1F5F9"))
    qapp.setPalette(palette)
    try:
        window = QWidget()
        qtbot.addWidget(window)
        window.setObjectName("workspace")
        layout = QVBoxLayout(window)
        combo = ThemedComboBox()
        combo.addItems(["All statuses", "Open", "Closed", "Archived"])
        layout.addWidget(combo)
        window.setStyleSheet(workspace_stylesheet())
        window.resize(360, 100)
        window.show()
        combo.showPopup()
        qtbot.waitUntil(lambda: combo.view().isVisible())
        assert isinstance(combo.view().itemDelegate(), QStyledItemDelegate)
        image = combo.view().viewport().grab().toImage()
        rect = combo.view().visualRect(combo.model().index(2, 0))
        assert image.pixelColor(rect.right() - 8, rect.center().y()).name() == (
            "#1b212b" if dark else "#ffffff"
        )
        image.save(str(tmp_path / "popup.png"))
        qtbot.keyClick(combo.view(), Qt.Key.Key_Down)
        qtbot.keyClick(combo.view(), Qt.Key.Key_Return)
        assert combo.currentText() == "Open"
    finally:
        qapp.setPalette(original)


def test_table_retains_row_selection_and_keyboard_focus(qtbot, tmp_path):
    window = QWidget()
    qtbot.addWidget(window)
    window.setObjectName("workspace")
    layout = QVBoxLayout(window)
    table = QTableWidget(2, 2)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setShowGrid(False)
    for row in range(2):
        for column in range(2):
            table.setItem(row, column, QTableWidgetItem(f"Case {row} / {column}"))
    layout.addWidget(table)
    window.setStyleSheet(workspace_stylesheet())
    window.show()
    table.setCurrentCell(0, 0)
    table.setFocus()
    qtbot.keyClick(table, Qt.Key.Key_Down)
    assert table.currentRow() == 1
    assert len(table.selectedItems()) == 2
    assert table.focusPolicy() != Qt.FocusPolicy.NoFocus
    table.grab().save(str(tmp_path / "table.png"))
