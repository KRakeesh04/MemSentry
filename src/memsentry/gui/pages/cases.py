"""Search, create, and open persisted workspace cases."""

from pathlib import Path

from PySide6.QtCore import QEvent, QObject, QSettings, Qt, Signal
from PySide6.QtGui import QColor, QMouseEvent
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from memsentry.app.case_service import (
    create_case,
    generate_case_number,
    update_case_status,
    workspace_database,
)
from memsentry.gui.controls import ThemedComboBox
from memsentry.models.case import Case, CaseStatus
from memsentry.storage.repositories.case_repository import CaseRepository


class CasesPage(QScrollArea):
    case_opened = Signal(str, object)
    workspace_loaded = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.cases: list[Case] = []
        self.visible_cases: list[Case] = []
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

        workspace_card = QFrame()
        workspace_card.setObjectName("card")

        workspace_layout = QVBoxLayout(workspace_card)
        workspace_layout.setContentsMargins(20, 16, 20, 16)
        workspace_layout.setSpacing(10)

        workspace_title = QLabel("Workspace")
        workspace_title.setObjectName("sectionTitle")
        workspace_layout.addWidget(workspace_title)

        workspace_hint = QLabel("Choose the folder where MemSentry stores and loads investigation cases.")
        workspace_hint.setWordWrap(True)
        workspace_layout.addWidget(workspace_hint)

        workspace_row = QHBoxLayout()

        self.workspace = QLineEdit(
            str(QSettings("MemSentry", "MemSentry").value("intake/workspace", ""))
        )
        self.workspace.setPlaceholderText("Workspace folder")
        self.workspace.setAccessibleName("Case workspace")
        workspace_row.addWidget(self.workspace, 1)

        browse = QPushButton("Browse…")
        browse.clicked.connect(self._browse)
        workspace_row.addWidget(browse)

        refresh = QPushButton("Refresh")
        refresh.clicked.connect(self.refresh)
        workspace_row.addWidget(refresh)

        workspace_layout.addLayout(workspace_row)

        layout.addWidget(workspace_card)

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
        self.table.setHorizontalHeaderLabels(["Name", "Case number", "Status", "Created (UTC)"])

        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Fixed)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Fixed)

        self.table.setColumnWidth(2, 100)
        self.table.setColumnWidth(3, 150)

        self.table.verticalHeader().hide()
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setMouseTracking(True)
        self.table.viewport().setMouseTracking(True)
        self.table.viewport().installEventFilter(self)
        self.table.setMinimumHeight(240)
        self.table.itemSelectionChanged.connect(self._selection_changed)
        self.table.cellDoubleClicked.connect(self.open_selected)
        layout.addWidget(self.table)
        self.message = QLabel()
        self.message.setWordWrap(True)
        layout.addWidget(self.message)

        self.reopen_button = QPushButton("Reopen")
        self.reopen_button.setEnabled(False)
        self.reopen_button.clicked.connect(
            lambda: self._change_selected_status(CaseStatus.OPEN)
        )

        self.close_button = QPushButton("Close")
        self.close_button.setEnabled(False)
        self.close_button.clicked.connect(
            lambda: self._change_selected_status(CaseStatus.CLOSED)
        )

        self.archive_button = QPushButton("Archive")
        self.archive_button.setEnabled(False)
        self.archive_button.clicked.connect(
            lambda: self._change_selected_status(CaseStatus.ARCHIVED)
        )

        self.open_button = QPushButton("Open selected case")
        self.open_button.setObjectName("primaryAction")
        self.open_button.setEnabled(False)
        self.open_button.setFixedWidth(180)
        self.open_button.clicked.connect(self.open_selected)

        open_row = QHBoxLayout()
        open_row.addStretch()
        open_row.addWidget(self.open_button)
        open_row.addWidget(self.reopen_button)
        open_row.addWidget(self.close_button)
        open_row.addWidget(self.archive_button)
        layout.addLayout(open_row)

        card = QFrame()
        card.setObjectName("card")
        form = QFormLayout(card)
        form.setContentsMargins(20, 18, 20, 20)
        form.setHorizontalSpacing(12)
        form.setVerticalSpacing(10)

        heading = QLabel("New case")
        heading.setObjectName("sectionTitle")
        form.addRow(heading)

        self.number = QLineEdit(generate_case_number())
        self.number.setToolTip("Automatically suggested; edit to use your own case number.")

        self.name = QLineEdit()
        self.name.setPlaceholderText("Give this investigation a clear name")

        self.description = QLineEdit()
        self.description.setPlaceholderText("Optional investigation notes")

        self.workspace.textChanged.connect(self._update_create_button)
        self.name.textChanged.connect(self._update_create_button)
        self.number.textChanged.connect(self._update_create_button)

        form.addRow("Case number", self.number)
        form.addRow("Case name *", self.name)
        form.addRow("Description", self.description)

        self.create_error = QLabel()
        self.create_error.setWordWrap(True)
        self.create_error.setObjectName("errorText")
        self.name.textChanged.connect(self.create_error.clear)
        self.number.textChanged.connect(self.create_error.clear)
        self.workspace.textChanged.connect(self.create_error.clear)
        form.addRow(self.create_error)

        self.create_button = QPushButton("Create and open case")
        self.create_button.setObjectName("primaryAction")
        self.create_button.clicked.connect(self._create)
        form.addRow(self.create_button)
        self._update_create_button()

        layout.addWidget(card)
        layout.addStretch()
        self.setWidget(content)
        self.workspace.textChanged.connect(self._workspace_edited)
        self.workspace.editingFinished.connect(self.refresh)
        if self.workspace.text():
            self.refresh()
        else:
            self.message.setText("Choose a workspace to see saved cases.")

    def eventFilter(self, watched: QObject, event: QEvent) -> bool:
        if watched is self.table.viewport():
            if isinstance(event, QMouseEvent) and event.type() == QEvent.Type.MouseMove:
                actionable = self.table.indexAt(event.position().toPoint()).isValid()
                self.table.viewport().setCursor(
                    Qt.CursorShape.PointingHandCursor
                    if actionable else Qt.CursorShape.ArrowCursor
                )
            elif event.type() == QEvent.Type.Leave:
                self.table.viewport().setCursor(Qt.CursorShape.ArrowCursor)
        return super().eventFilter(watched, event)

    def _update_create_button(self) -> None:
        valid = bool(
            self.workspace.text().strip()
            and self.name.text().strip()
            and self.number.text().strip()
        )

        self.create_button.setEnabled(valid)

    def _workspace_edited(self) -> None:
        self.cases = []
        self.loaded_workspace = ""
        self._render()

    def _browse(self) -> None:
        path = QFileDialog.getExistingDirectory(self, "Choose workspace", self.workspace.text())
        if path:
            self.workspace.setText(path)
            self.refresh()

    def refresh(self) -> None:
        self.cases = []
        self.loaded_workspace = ""
        try:
            database = workspace_database(self.workspace.text())
            folder = Path(self.workspace.text().strip()).expanduser().resolve()
            if (folder / "memsentry.sqlite3").is_file():
                self.cases = CaseRepository(database).list_all()
            self.loaded_workspace = str(folder)
            QSettings("MemSentry", "MemSentry").setValue("intake/workspace", str(folder))
            self.workspace_loaded.emit(self.loaded_workspace)
            self._render()
        except Exception as exc:
            self._render()
            self.message.setText(f"Could not load cases: {exc}")

    def _render(self) -> None:
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
                    case.name,
                    case.case_number,
                    case.status.title(),
                    case.created_at.strftime("%Y-%m-%d %H:%M"),
                )
            ):
                item = QTableWidgetItem(value)
                item.setToolTip(value)

                if column in (1, 2):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)

                self.table.setItem(row, column, item)
                if column == 2:
                    if case.status == "open":
                        item.setForeground(QColor("#4ade80"))
                    elif case.status == "closed":
                        item.setForeground(QColor("#94a3b8"))
                    elif case.status == "archived":
                        item.setForeground(QColor("#fbbf24"))

            self.table.setRowHeight(row, 48)
        self.message.setText(
            f"{len(self.visible_cases)} saved cases"
            if self.visible_cases
            else "No matching cases. Create a case below to get started."
        )
        self._selection_changed()

    def _selection_changed(self) -> None:
        row = self.table.currentRow()
        has_selection = bool(self.table.selectedItems()) and 0 <= row < len(self.visible_cases)

        self.open_button.setEnabled(False)
        self.close_button.setEnabled(False)
        self.archive_button.setEnabled(False)
        self.reopen_button.setEnabled(False)

        if not has_selection:
            return

        case = self.visible_cases[row]

        if case.status == CaseStatus.OPEN.value:
            self.open_button.setEnabled(True)
            self.close_button.setEnabled(True)

        elif case.status == CaseStatus.CLOSED.value:
            self.archive_button.setEnabled(True)
            self.reopen_button.setEnabled(True)

        elif case.status == CaseStatus.ARCHIVED.value:
            self.reopen_button.setEnabled(True)

    def open_selected(self, *_: object) -> None:
        row = self.table.currentRow()

        if not self.table.selectedItems() or not 0 <= row < len(self.visible_cases):
            return

        case = self.visible_cases[row]

        if case.status != CaseStatus.OPEN.value:
            return

        self.case_opened.emit(self.loaded_workspace, case)

    def _change_selected_status(self, status: CaseStatus) -> None:
        row = self.table.currentRow()

        if not self.table.selectedItems() or not 0 <= row < len(self.visible_cases):
            return

        case = self.visible_cases[row]

        current_status = case.status

        allowed = (
            (current_status == CaseStatus.OPEN.value and status == CaseStatus.CLOSED)
            or (current_status == CaseStatus.CLOSED.value and status == CaseStatus.ARCHIVED)
            or (
                current_status in (
                    CaseStatus.CLOSED.value,
                    CaseStatus.ARCHIVED.value,
                )
                and status == CaseStatus.OPEN
            )
        )

        if not allowed:
            self.message.setText("That case status change is not allowed.")
            return

        if status == CaseStatus.CLOSED:
            action = "close"

        elif status == CaseStatus.ARCHIVED:
            action = "archive"

        else:
            action = "reopen"

        if status == CaseStatus.ARCHIVED:
            message = (
                f"Archive case '{case.name}'?\n\n"
                "Archived cases cannot be opened until they are reopened."
            )
        else:
            message = f"Are you sure you want to {action} case '{case.name}'?"

        reply = QMessageBox.question(
            self,
            "Confirm change",
            message,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No,
        )

        if reply != QMessageBox.StandardButton.Yes:
            return

        try:
            update_case_status(
                self.loaded_workspace,
                case.id,
                status,
            )
        except Exception as exc:
            self.message.setText(f"Could not update case status: {exc}")
            return

        self.refresh()

    def _create(self) -> None:
        self.create_error.clear()

        if not self.workspace.text().strip():
            self.create_error.setText("Choose a workspace before creating a case.")
            return

        if not self.name.text().strip():
            self.create_error.setText("Enter a case name.")
            self.name.setFocus()
            return

        if not self.number.text().strip():
            self.create_error.setText("Case number cannot be empty.")
            self.number.setFocus()
            return

        try:
            case = create_case(
                self.workspace.text(),
                self.number.text(),
                self.name.text(),
                self.description.text(),
            )
        except Exception as exc:
            message = str(exc)
            if "UNIQUE constraint failed: cases.case_number" in message:
                message = f"Case number '{self.number.text().strip()}' already exists."
            else:
                message = f"Could not create case: {message}"
            self.create_error.setText(message)
            self.message.setText(message)
            return
        self.create_error.clear()
        self.refresh()
        self.number.setText(generate_case_number())
        self.name.clear()
        self.description.clear()
        self.case_opened.emit(self.loaded_workspace, case)


def create_page() -> CasesPage:
    return CasesPage()
