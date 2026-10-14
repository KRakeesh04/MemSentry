from __future__ import annotations

from collections.abc import Iterable

from PySide6.QtCore import Qt
from PySide6.QtGui import QGuiApplication
from PySide6.QtWidgets import (
    QDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)


class DetailsDialog(QDialog):
    def __init__(
        self,
        title: str,
        heading: str,
        fields: Iterable[tuple[str, str]],
        details: str | None = None,
        description: str | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)

        self.setWindowTitle(title)
        self.resize(720, 560)
        self.setMinimumSize(640, 480)

        root = QVBoxLayout(self)
        root.setContentsMargins(16, 16, 16, 12)
        root.setSpacing(12)

        # Main content card
        card = QFrame()
        card.setObjectName("card")

        card_layout = QVBoxLayout(card)
        card_layout.setContentsMargins(28, 24, 28, 24)
        card_layout.setSpacing(16)

        heading_label = QLabel(heading)
        heading_label.setObjectName("dialogHeading")
        heading_label.setWordWrap(True)
        card_layout.addWidget(heading_label)

        if description:
            description_label = QLabel(description)
            description_label.setWordWrap(True)
            description_label.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )
            card_layout.addWidget(description_label)

        # Metadata
        field_container = QWidget()
        field_layout = QVBoxLayout(field_container)
        field_layout.setContentsMargins(0, 0, 0, 0)
        field_layout.setSpacing(8)

        for label_text, value_text in fields:
            row = QHBoxLayout()
            row.setSpacing(18)

            field_label = QLabel(label_text)
            field_label.setObjectName("muted")
            field_label.setFixedWidth(140)

            field_value = QLabel(value_text or "N/A")
            field_value.setWordWrap(True)
            field_value.setTextInteractionFlags(
                Qt.TextInteractionFlag.TextSelectableByMouse
            )

            row.addWidget(field_label)
            row.addWidget(field_value, 1)

            field_layout.addLayout(row)

        card_layout.addWidget(field_container)

        if details:
            details_label = QLabel("Details")
            details_label.setObjectName("sectionTitle")
            card_layout.addWidget(details_label)

            details_box = QTextEdit()
            details_box.setReadOnly(True)
            details_box.setPlainText(details)
            details_box.setMinimumHeight(180)

            card_layout.addWidget(details_box)

        root.addWidget(card, 1)

        # Bottom controls
        footer = QHBoxLayout()

        copy_button = QPushButton("Copy details")
        copy_button.clicked.connect(
            lambda: QGuiApplication.clipboard().setText(
                self._compose_copy_text(
                    heading,
                    fields,
                    description,
                    details,
                )
            )
        )

        close_button = QPushButton("Close")
        close_button.setObjectName("primaryButton")
        close_button.clicked.connect(self.accept)

        footer.addWidget(copy_button)
        footer.addStretch()
        footer.addWidget(close_button)

        root.addLayout(footer)

    @staticmethod
    def _compose_copy_text(
        heading: str,
        fields: Iterable[tuple[str, str]],
        description: str | None,
        details: str | None,
    ) -> str:
        parts = [heading]

        if description:
            parts.extend(["", description])

        parts.append("")

        for label_text, value_text in fields:
            parts.append(f"{label_text}: {value_text or 'N/A'}")

        if details:
            parts.extend(["", details])

        return "\n".join(parts)