"""Presentation-only pages containing synthetic preview data."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)


def create_placeholder(name: str, content: tuple) -> QScrollArea:
    """Build a scrollable page; no preview action executes forensic work."""
    description, metrics, section, headers, rows, action = content
    scroll = QScrollArea()
    scroll.setWidgetResizable(True)
    scroll.setFrameShape(QFrame.Shape.NoFrame)
    scroll.setAccessibleName(name)
    page = QWidget()
    layout = QVBoxLayout(page)
    layout.setContentsMargins(32, 32, 32, 32)
    layout.setSpacing(24)

    heading = QHBoxLayout()
    title = QLabel(name)
    title.setObjectName("pageTitle")
    heading.addWidget(title, 1)
    if action:
        button = QPushButton(action.replace("&", "&&"))
        button.setEnabled(False)
        button.setToolTip("UI preview — this action is not connected yet.")
        heading.addWidget(button)
    layout.addLayout(heading)
    subtitle = QLabel(description)
    subtitle.setObjectName("muted")
    subtitle.setWordWrap(True)
    layout.addWidget(subtitle)

    cards = QHBoxLayout()
    cards.setSpacing(16)
    for label, value in metrics:
        card = QFrame()
        card.setObjectName("card")
        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(20, 20, 20, 20)
        caption = QLabel(label)
        caption.setObjectName("muted")
        caption.setWordWrap(True)
        metric = QLabel(value)
        metric.setObjectName("metric")
        metric.setWordWrap(True)
        card_layout.addWidget(caption)
        card_layout.addWidget(metric)
        cards.addWidget(card, 1)
    layout.addLayout(cards)

    section_label = QLabel(section)
    section_label.setObjectName("sectionTitle")
    layout.addWidget(section_label)
    table = QTableWidget(len(rows), len(headers))
    table.setAccessibleName(section)
    table.setHorizontalHeaderLabels(headers)
    table.verticalHeader().hide()
    table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
    table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
    table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
    table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
    table.setShowGrid(False)
    table.setWordWrap(True)
    for row_index, row in enumerate(rows):
        for column, value in enumerate(row):
            item = QTableWidgetItem(value)
            item.setToolTip(value)
            item.setTextAlignment(Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft)
            table.setItem(row_index, column, item)
        table.setRowHeight(row_index, 52)
    table.setMinimumHeight(64 + 52 * len(rows))
    layout.addWidget(table)
    layout.addStretch()
    scroll.setWidget(page)
    return scroll
