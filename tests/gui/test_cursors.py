from PySide6.QtCore import Qt
from PySide6.QtWidgets import QAbstractButton, QComboBox, QLineEdit, QPushButton

from memsentry.gui.main_window import MainWindow


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
