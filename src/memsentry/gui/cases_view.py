"""Display, create, and open persisted investigation cases in MemSentry."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from memsentry.gui.create_case_dialog import CreateCaseDialog
from memsentry.gui.theme import create_card_frame
from memsentry.models.case import Case
from memsentry.storage.repositories.case_repository import CaseRepository


class CasesView(QWidget):
    """Display and open persisted investigation cases with modern DFIR styling."""

    case_opened = Signal(object)

    def __init__(self, case_repository: CaseRepository, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.case_repository = case_repository
        self._build_ui()
        self.load_cases()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 24, 24, 24)
        layout.setSpacing(20)

        # Header bar
        header_box = QHBoxLayout()

        title_layout = QVBoxLayout()
        self.title_label = QLabel("Investigation Cases")
        self.title_label.setObjectName("ViewTitle")
        self.title_label.setStyleSheet("color: #F9FAFB; font-size: 22px; font-weight: 800;")

        self.subtitle_label = QLabel("Open an active digital forensic case or initialize a new incident investigation.")
        self.subtitle_label.setStyleSheet("color: #9CA3AF; font-size: 12px;")

        title_layout.addWidget(self.title_label)
        title_layout.addWidget(self.subtitle_label)

        header_box.addLayout(title_layout)
        header_box.addStretch()

        self.open_button = QPushButton("Open Case")
        self.open_button.setObjectName("primaryButton")
        self.open_button.setEnabled(False)
        self.open_button.clicked.connect(self.open_selected_case)

        self.create_button = QPushButton("+ Create Case")
        self.create_button.clicked.connect(self.open_create_dialog)

        header_box.addWidget(self.open_button)
        header_box.addWidget(self.create_button)

        layout.addLayout(header_box)

        # Table Container Card Frame
        table_card = create_card_frame()
        card_layout = QVBoxLayout(table_card)
        card_layout.setContentsMargins(16, 16, 16, 16)

        self.state_label = QLabel("Loading cases...")
        self.state_label.setStyleSheet("color: #6B7280; font-size: 11px; font-weight: 600; margin-bottom: 8px;")

        self.case_table = QTableWidget(0, 4)
        self.case_table.setHorizontalHeaderLabels(["Case Number", "Investigation Name", "Status", "Created At"])
        self.case_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.case_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.case_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.case_table.setSortingEnabled(True)
        self.case_table.itemSelectionChanged.connect(self.update_open_state)
        self.case_table.cellDoubleClicked.connect(self.open_selected_case)
        self.case_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)

        card_layout.addWidget(self.state_label)
        card_layout.addWidget(self.case_table)

        layout.addWidget(table_card)

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
            num_item = QTableWidgetItem(case.case_number)
            num_item.setData(Qt.ItemDataRole.UserRole, case)

            name_item = QTableWidgetItem(case.name)
            status_str = case.status.value.upper()
            status_item = QTableWidgetItem(status_str)
            date_item = QTableWidgetItem(case.created_at.astimezone().strftime("%Y-%m-%d %H:%M"))

            self.case_table.setItem(row, 0, num_item)
            self.case_table.setItem(row, 1, name_item)
            self.case_table.setItem(row, 2, status_item)
            self.case_table.setItem(row, 3, date_item)

        self.case_table.setSortingEnabled(True)
        self.state_label.setText(
            "No investigations yet. Create a case to begin."
            if not cases
            else f"{len(cases)} active investigation(s) in repository"
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
