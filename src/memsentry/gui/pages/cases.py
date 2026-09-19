"""Search, create, and open persisted workspace cases."""

from pathlib import Path

from PySide6.QtCore import QSettings, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from memsentry.app.case_service import create_case, generate_case_number, workspace_database
from memsentry.gui.controls import ThemedComboBox
from memsentry.storage.repositories.case_repository import CaseRepository


class CasesPage(QScrollArea):
    case_opened = Signal(str, object)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.cases = []
        self.visible_cases = []
        self.loaded_workspace = ""
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(16)
        title = QLabel("Cases")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        layout.addWidget(QLabel("Create an investigation or continue a saved case."))
        row = QHBoxLayout()
        self.workspace = QLineEdit(
            str(QSettings("MemSentry", "MemSentry").value("intake/workspace", ""))
        )
        self.workspace.setPlaceholderText("Workspace folder")
        self.workspace.setAccessibleName("Case workspace")
        row.addWidget(self.workspace, 1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        row.addWidget(browse)
        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        row.addWidget(refresh)
        layout.addLayout(row)
        filters = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search case number, name, or description")
        self.search.setClearButtonEnabled(True)
        self.search.textChanged.connect(self._render)
        filters.addWidget(self.search, 1)
        self.status = ThemedComboBox()
        self.status.addItems(["All statuses", "Open", "Closed", "Archived"])
        self.status.currentIndexChanged.connect(self._render)
        filters.addWidget(self.status)
        layout.addLayout(filters)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Case number", "Name", "Status", "Created (UTC)"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Stretch)
        self.table.verticalHeader().hide()
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setMinimumHeight(240)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.table.cellDoubleClicked.connect(self.open_selected)
        layout.addWidget(self.table)
        self.message = QLabel()
        self.message.setWordWrap(True)
        layout.addWidget(self.message)
        self.open_button = QPushButton("Open selected case")
        self.open_button.setObjectName("primaryAction")
        self.open_button.setEnabled(False)
        self.open_button.clicked.connect(self.open_selected)
        layout.addWidget(self.open_button)
        card = QFrame()
        card.setObjectName("card")
        form = QFormLayout(card)
        form.setContentsMargins(20, 20, 20, 20)
        heading = QLabel("New case")
        heading.setObjectName("sectionTitle")
        form.addRow(heading)
        self.number = QLineEdit(generate_case_number())
        self.number.setToolTip("Automatically suggested; edit to use your own case number.")
        self.name = QLineEdit()
        self.name.setPlaceholderText("Give this investigation a clear name")
        self.description = QLineEdit()
        self.description.setPlaceholderText("Optional investigation notes")
        form.addRow("Case number", self.number)
        form.addRow("Case name", self.name)
        form.addRow("Description", self.description)
        self.create_button = QPushButton("Create and open case")
        self.create_button.clicked.connect(self._create)
        form.addRow(self.create_button)
        layout.addWidget(card)
        layout.addStretch()
        self.setWidget(content)
        self.workspace.textChanged.connect(self._workspace_edited)
        self.workspace.editingFinished.connect(self.refresh)
        if self.workspace.text():
            self.refresh()
        else:
            self.message.setText("Choose a workspace to see saved cases.")

    def _workspace_edited(self):
        self.cases = []
        self.loaded_workspace = ""
        self._render()

    def _browse(self):
        path = QFileDialog.getExistingDirectory(self, "Choose workspace", self.workspace.text())
        if path:
            self.workspace.setText(path)
            self.refresh()

    def refresh(self):
        self.cases = []
        self.loaded_workspace = ""
        try:
            database = workspace_database(self.workspace.text())
            folder = Path(self.workspace.text().strip()).expanduser().resolve()
            if (folder / "memsentry.sqlite3").is_file():
                self.cases = CaseRepository(database).list_all()
            self.loaded_workspace = str(folder)
            QSettings("MemSentry", "MemSentry").setValue("intake/workspace", str(folder))
            self._render()
        except Exception as exc:
            self._render()
            self.message.setText(f"Could not load cases: {exc}")

    def _render(self):
        query = self.search.text().strip().casefold()
        status = self.status.currentText().lower()
        self.visible_cases = [
            case
            for case in self.cases
            if (not self.status.currentIndex() or case.status == status)
            and query in f"{case.case_number} {case.name} {case.description or ''}".casefold()
        ]
        self.table.setRowCount(0)
        self.table.setRowCount(len(self.visible_cases))
        for row, case in enumerate(self.visible_cases):
            for column, value in enumerate(
                (
                    case.case_number,
                    case.name,
                    case.status.title(),
                    case.created_at.strftime("%Y-%m-%d %H:%M"),
                )
            ):
                item = QTableWidgetItem(value)
                item.setToolTip(value)
                self.table.setItem(row, column, item)
            self.table.setRowHeight(row, 48)
        self.message.setText(
            f"{len(self.visible_cases)} saved cases"
            if self.visible_cases
            else "No matching cases. Create a case below to get started."
        )
        self._selection_changed()

    def _selection_changed(self):
        self.open_button.setEnabled(bool(self.table.selectedItems()))

    def open_selected(self, *_):
        row = self.table.currentRow()
        if self.table.selectedItems() and 0 <= row < len(self.visible_cases):
            self.case_opened.emit(self.loaded_workspace, self.visible_cases[row])

    def _create(self):
        try:
            case = create_case(
                self.workspace.text(), self.number.text(), self.name.text(), self.description.text()
            )
        except Exception as exc:
            self.message.setText(f"Could not create case: {exc}")
            return
        self.refresh()
        self.number.setText(generate_case_number())
        self.name.clear()
        self.description.clear()
        self.case_opened.emit(self.loaded_workspace, case)


def create_page():
    return CasesPage()
