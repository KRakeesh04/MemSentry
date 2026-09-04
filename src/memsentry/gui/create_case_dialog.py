from __future__ import annotations

from PySide6.QtCore import Signal
from PySide6.QtWidgets import (
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QLabel,
    QLineEdit,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from memsentry.models.case import CaseCreate
from memsentry.storage.repositories.case_repository import (
    CaseRepository,
    DuplicateCaseNumberError,
)


class CreateCaseDialog(QDialog):
    """Collect case metadata and persist it through CaseRepository."""

    case_created = Signal(object)

    def __init__(self, case_repository: CaseRepository, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.case_repository = case_repository
        self.setWindowTitle("Create Case")
        self.setModal(True)

        self.case_number_input = QLineEdit()
        self.case_number_input.setPlaceholderText("Case number")
        self.name_input = QLineEdit()
        self.name_input.setPlaceholderText("Investigation name")
        self.description_input = QTextEdit()
        self.description_input.setPlaceholderText("Optional description")
        self.error_label = QLabel()
        self.error_label.setObjectName("formError")
        self.error_label.setWordWrap(True)

        form = QFormLayout()
        form.addRow("Case number", self.case_number_input)
        form.addRow("Name", self.name_input)
        form.addRow("Description", self.description_input)

        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        buttons.addButton("Create", QDialogButtonBox.ButtonRole.AcceptRole)
        buttons.accepted.connect(self.create_case)
        buttons.rejected.connect(self.reject)

        layout = QVBoxLayout(self)
        layout.addWidget(QLabel("Create a new forensic investigation"))
        layout.addLayout(form)
        layout.addWidget(self.error_label)
        layout.addWidget(buttons)

    def create_case(self) -> None:
        """Validate the form and create a case through the repository."""
        case_number = self.case_number_input.text().strip()
        name = self.name_input.text().strip()

        if not case_number or not name:
            self.show_error("Case number and name are required.")
            return

        try:
            case = self.case_repository.create(
                CaseCreate(
                    case_number=case_number,
                    name=name,
                    description=self.description_input.toPlainText().strip() or None,
                )
            )
        except DuplicateCaseNumberError:
            self.show_error("That case number already exists.")
            return
        except Exception as exc:
            self.show_error(f"Could not create case: {exc}")
            return

        self.case_created.emit(case)
        self.accept()

    def show_error(self, message: str) -> None:
        self.error_label.setText(message)
