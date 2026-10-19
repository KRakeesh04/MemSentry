from PySide6.QtCore import QEvent, QPointF, Qt
from PySide6.QtGui import QMouseEvent
from PySide6.QtWidgets import (
    QAbstractButton,
    QApplication,
    QComboBox,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QTableWidgetItem,
)

from memsentry.gui.main_window import MainWindow
from memsentry.gui.pages.cases import CasesPage


def test_interactive_controls_and_disabled_states(qtbot):
    window = MainWindow()
    qtbot.addWidget(window)
    for kind in (QAbstractButton, QComboBox):
        for control in window.findChildren(kind):
            expected = (
                Qt.CursorShape.PointingHandCursor
                if control.isEnabled()
                else Qt.CursorShape.ArrowCursor
            )
            assert control.cursor().shape() == expected
    for field in window.findChildren(QLineEdit):
        assert field.cursor().shape() != Qt.CursorShape.PointingHandCursor

    button = window.evidence_page.start
    button.setEnabled(False)
    assert button.cursor().shape() == Qt.CursorShape.ArrowCursor
    button.setEnabled(True)
    assert button.cursor().shape() == Qt.CursorShape.PointingHandCursor

    window.sidebar.setEnabled(False)
    for button in window.sidebar.findChildren(QPushButton):
        assert button.cursor().shape() == Qt.CursorShape.ArrowCursor
    window.sidebar.setEnabled(True)
    for button in window.sidebar.findChildren(QPushButton):
        assert button.cursor().shape() == Qt.CursorShape.PointingHandCursor


def test_dynamic_controls_receive_cursor_without_affecting_other_windows(qtbot):
    window = MainWindow()
    qtbot.addWidget(window)
    button = QPushButton("New action", window)
    button.ensurePolished()
    assert button.cursor().shape() == Qt.CursorShape.PointingHandCursor
    unrelated = QPushButton("Outside application window")
    qtbot.addWidget(unrelated)
    unrelated.ensurePolished()
    assert unrelated.cursor().shape() == Qt.CursorShape.ArrowCursor


def test_popup_buttons_receive_pointer_cursors(qtbot):
    window = MainWindow()
    qtbot.addWidget(window)
    for parent in (window, window.overview_page):
        dialog = QMessageBox(parent)
        qtbot.addWidget(dialog)
        dialog.setStandardButtons(QMessageBox.StandardButton.Ok)
        dialog.show()
        button = dialog.button(QMessageBox.StandardButton.Ok)
        assert button.cursor().shape() == Qt.CursorShape.PointingHandCursor
        button.setEnabled(False)
        assert button.cursor().shape() == Qt.CursorShape.ArrowCursor
        button.setEnabled(True)
        assert button.cursor().shape() == Qt.CursorShape.PointingHandCursor
        dialog.close()


def test_case_table_rows_show_pointer_cursor(qtbot):
    page = CasesPage()
    qtbot.addWidget(page)
    page.resize(1000, 700)
    page.table.setRowCount(1)
    page.table.setItem(0, 0, QTableWidgetItem("Case row"))
    page.show()
    qtbot.waitExposed(page)
    row_rect = page.table.visualRect(page.table.model().index(0, 0))
    viewport = page.table.viewport()
    for position, expected in (
        (row_rect.center(), Qt.CursorShape.PointingHandCursor),
        (viewport.rect().bottomRight(), Qt.CursorShape.ArrowCursor),
    ):
        # Deliver the event directly: Wayland does not support QTest cursor warping.
        event = QMouseEvent(
            QEvent.Type.MouseMove,
            QPointF(position),
            QPointF(viewport.mapToGlobal(position)),
            Qt.MouseButton.NoButton,
            Qt.MouseButton.NoButton,
            Qt.KeyboardModifier.NoModifier,
        )
        QApplication.sendEvent(viewport, event)
        assert viewport.cursor().shape() == expected
