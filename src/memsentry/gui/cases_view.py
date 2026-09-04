from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from memsentry.gui.create_case_dialog import CreateCaseDialog
from memsentry.models.case import Case
from memsentry.storage.repositories.case_repository import CaseRepository


class CasesView(QWidget):
    """Display and open persisted cases."""

    case_opened = Signal(object)

    def __init__(self, case_repository: CaseRepository, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.case_repository = case_repository
        self._build_ui()
        self.load_cases()

    def _build_ui(self) -> None:
        self.title_label = QLabel("Forensic investigations")
        self.title_label.setObjectName("pageTitle")
        self.subtitle_label = QLabel("Open an existing case or create a new investigation.")
        self.state_label = QLabel()
        self.state_label.setObjectName("stateLabel")

        self.create_button = QPushButton("Create case")
        self.create_button.clicked.connect(self.open_create_dialog)
        self.open_button = QPushButton("Open case")
        self.open_button.setEnabled(False)
        self.open_button.clicked.connect(self.open_selected_case)

        actions = QHBoxLayout()
        actions.addStretch()
        actions.addWidget(self.open_button)
        actions.addWidget(self.create_button)

        self.case_table = QTableWidget(0, 4)
        self.case_table.setHorizontalHeaderLabels(
            ["Case number", "Name", "Status", "Created"]
        )
        self.case_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.case_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.case_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.case_table.setSortingEnabled(True)
        self.case_table.itemSelectionChanged.connect(self.update_open_state)
        self.case_table.cellDoubleClicked.connect(self.open_selected_case)
        self.case_table.horizontalHeader().setStretchLastSection(True)

        layout = QVBoxLayout(self)
        layout.addWidget(self.title_label)
        layout.addWidget(self.subtitle_label)
        layout.addLayout(actions)
        layout.addWidget(self.state_label)
        layout.addWidget(self.case_table)

    def load_cases(self) -> None:
        """Load cases and expose loading, empty, and error states."""
        self.state_label.setText("Loading cases...")
        self.case_table.setRowCount(0)
        try:
            cases = self.case_repository.list_all()
        except Exception as exc:
            self.state_label.setText(f"Unable to load cases: {exc}")
            return

        self.populate_cases(cases)

    def populate_cases(self, cases: list[Case]) -> None:
        self.case_table.setSortingEnabled(False)
        self.case_table.setRowCount(len(cases))
        for row, case in enumerate(cases):
            values = [
                case.case_number,
                case.name,
                case.status.value,
                case.created_at.astimezone().strftime("%Y-%m-%d %H:%M"),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, case)
                self.case_table.setItem(row, column, item)
        self.case_table.setSortingEnabled(True)
        self.state_label.setText(
            "No investigations yet. Create a case to begin."
            if not cases
            else f"{len(cases)} investigation(s)"
        )
        self.update_open_state()

    def update_open_state(self) -> None:
        self.open_button.setEnabled(self.case_table.currentRow() >= 0)

    def open_create_dialog(self) -> None:
        dialog = CreateCaseDialog(self.case_repository, self)
        dialog.case_created.connect(self.handle_case_created)
        dialog.exec()

    def handle_case_created(self, case: Case) -> None:
        self.load_cases()
        self.select_case(case)

    def select_case(self, case: Case) -> None:
        for row in range(self.case_table.rowCount()):
            item = self.case_table.item(row, 0)
            row_case = item.data(Qt.ItemDataRole.UserRole) if item is not None else None
            if isinstance(row_case, Case) and row_case.id == case.id:
                self.case_table.selectRow(row)
                return

    def open_selected_case(self) -> None:
        row = self.case_table.currentRow()
        if row < 0:
            return
        case_id_item = self.case_table.item(row, 0)
        if case_id_item is None:
            return
        case = case_id_item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(case, Case):
            return
        stored_case = self.case_repository.get_by_id(case.id)
        if stored_case is not None:
            self.case_opened.emit(stored_case)
