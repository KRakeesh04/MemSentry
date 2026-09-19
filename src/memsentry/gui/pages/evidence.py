"""Memory-image import and live acquisition backed by the intake service."""

import platform
from pathlib import Path
from threading import Event

from PySide6.QtCore import QSettings, QThread, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from memsentry.acquisition.config import load_environment_file
from memsentry.acquisition.tool_catalog import available_tools
from memsentry.app.intake_service import IntakeRequest, IntakeService
from memsentry.gui.intake_widgets import ChoiceCard, FileDropArea, SystemCard
from memsentry.models.evidence import EvidenceOS


class IntakeWorker(QThread):
    progress = Signal(str, int)
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, request: IntakeRequest, parent=None, service=None) -> None:
        super().__init__(parent)
        self.request = request
        self.service = service or IntakeService()
        self.cancelled = Event()

    def run(self) -> None:
        try:
            result = self.service.run(self.request, self.progress.emit, self.cancelled)
        except Exception as exc:
            self.failed.emit(str(exc))
        else:
            self.succeeded.emit(result)


class EvidencePage(QScrollArea):
    status_changed = Signal(str)
    evidence_registered = Signal(object)

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self.worker = None
        self.setAccessibleName("Memory evidence intake")
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.settings = QSettings("MemSentry", "MemSentry")
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(20)
        title = QLabel("Add memory evidence")
        title.setObjectName("pageTitle")
        layout.addWidget(title)
        intro = QLabel(
            "Import a captured image or acquire RAM from this computer. "
            "Evidence is hashed, verified, and registered to your case."
        )
        intro.setWordWrap(True)
        intro.setObjectName("muted")
        layout.addWidget(intro)

        self.form = QFrame()
        self.form.setObjectName("card")
        form_layout = QVBoxLayout(self.form)
        form_layout.setContentsMargins(24, 24, 24, 24)
        form_layout.setSpacing(16)
        self.mode = QComboBox(self.form)
        self.mode.addItems(["Import memory image", "Live memory acquisition"])
        self.mode.setAccessibleName("Evidence source")
        self.mode.hide()
        mode_cards = QHBoxLayout()
        self.mode_buttons = QButtonGroup(self)
        for index, (name, description) in enumerate(
            (
                ("Import Memory Dump", "Load an existing memory image"),
                ("Live Memory Acquisition", "Capture RAM from this computer"),
            )
        ):
            card = ChoiceCard(name, description)
            self.mode_buttons.addButton(card, index)
            mode_cards.addWidget(card, 1)
        self.mode_buttons.idClicked.connect(self.mode.setCurrentIndex)
        form_layout.addLayout(mode_cards)
        self.mode_hint = QLabel()
        self.mode_hint.setWordWrap(True)
        self.mode_hint.setObjectName("muted")
        form_layout.addWidget(self.mode_hint)
        form = QFormLayout()
        form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        form.setSpacing(12)
        self.workspace = QLineEdit(str(self.settings.value("intake/workspace", "")))
        self.workspace.setPlaceholderText("Folder for case database, captures, and audit records")
        self.case_number = QLineEdit()
        self.case_number.setPlaceholderText("e.g. CASE-2026-001")
        self.case_name = QLineEdit()
        self.case_name.setPlaceholderText("New case name, or the exact name of an existing case")
        form.addRow("Workspace", self._path_row(self.workspace, directory=True))
        case_row = QWidget()
        case_layout = QHBoxLayout(case_row)
        case_layout.setContentsMargins(0, 0, 0, 0)
        self.existing_cases = QComboBox()
        self.existing_cases.addItem("Create a new case", None)
        self.existing_cases.currentIndexChanged.connect(self._select_case)
        case_layout.addWidget(self.existing_cases, 1)
        refresh = QPushButton("Load cases")
        refresh.clicked.connect(self._load_cases)
        case_layout.addWidget(refresh)
        form.addRow("Case", case_row)
        form.addRow("Case number", self.case_number)
        form.addRow("Case name", self.case_name)

        self.import_fields = QWidget()
        import_form = QFormLayout(self.import_fields)
        import_form.setContentsMargins(0, 0, 0, 0)
        import_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.source = QLineEdit()
        self.source.setPlaceholderText("Select a .raw, .mem, .lime, or other memory image")
        self.drop_area = FileDropArea()
        self.drop_area.clicked.connect(lambda: self._browse(self.source, False))
        self.drop_area.file_selected.connect(self.source.setText)
        self.drop_area.invalid_drop.connect(self._failed)
        import_form.addRow(self.drop_area)
        import_form.addRow("Selected image", self._path_row(self.source))
        self.file_details = QLabel("No file selected · original evidence stays read-only")
        self.file_details.setObjectName("muted")
        self.file_details.setWordWrap(True)
        self.source.textChanged.connect(self._file_selected)
        import_form.addRow(self.file_details)
        self.os_choice = QComboBox()
        self.os_choice.addItems(["Unknown / identify during analysis", "Windows", "Linux", "macOS"])
        import_form.addRow("Image OS", self.os_choice)
        form_layout.addWidget(self.import_fields)

        self.live_fields = QWidget()
        live_form = QFormLayout(self.live_fields)
        live_form.setContentsMargins(0, 0, 0, 0)
        live_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        live_form.addRow(SystemCard())
        live_form.addRow(QLabel("Acquisition tool"))
        load_env = QPushButton("Load .env…")
        load_env.setToolTip("Load tool paths; existing environment variables take precedence.")
        load_env.clicked.connect(self._load_environment)
        live_form.addRow(load_env)
        self.tool_choices = QButtonGroup(self)
        self.configured_tools = available_tools()
        for index, option in enumerate(self.configured_tools):
            card = ChoiceCard(f"{option.name} · {option.host}", option.description)
            card.setEnabled(option.available)
            card.setToolTip(option.description)
            self.tool_choices.addButton(card, index)
            live_form.addRow(card)
        custom = ChoiceCard(
            "Choose another executable", "Browse for AVML on Linux or WinPmem mini on Windows"
        )
        custom.setEnabled(platform.system() in ("Linux", "Windows"))
        self.custom_tool_id = len(self.configured_tools)
        self.tool_choices.addButton(custom, self.custom_tool_id)
        live_form.addRow(custom)
        self.tool = QLineEdit(str(self.settings.value("intake/tool", "")))
        self.tool.setPlaceholderText("Optional: uses MEMSENTRY_AVML / MEMSENTRY_WINPMEM or PATH")
        self.custom_tool_row = self._path_row(self.tool)
        live_form.addRow(self.custom_tool_row)
        self.tool.setPlaceholderText("Path to a compatible acquisition executable")
        self.tool_choices.idClicked.connect(self._tool_selected)
        selected = next(
            (i for i, option in enumerate(self.configured_tools) if option.available),
            self.custom_tool_id,
        )
        self.tool_choices.button(selected).setChecked(True)
        self._tool_selected(selected)
        self.profile = QComboBox()
        self.profile.addItems(
            ["AVML legacy: avml output.lime", "AVML current: avml acquire output.lime"]
        )
        if platform.system() == "Linux":
            live_form.addRow("AVML version", self.profile)
        else:
            self.profile.setParent(self.live_fields)
            self.profile.hide()
        self.authorized = QCheckBox("I am authorized to capture memory on this host.")
        live_form.addRow(self.authorized)
        form_layout.addWidget(self.live_fields)
        case_heading = QLabel("Case & storage")
        case_heading.setObjectName("sectionTitle")
        form_layout.addWidget(case_heading)
        form_layout.addLayout(form)
        layout.addWidget(self.form)

        actions = QHBoxLayout()
        self.start = QPushButton("Import and verify")
        self.start.setObjectName("primaryAction")
        self.cancel = QPushButton("Cancel")
        self.cancel.setEnabled(False)
        actions.addWidget(self.start)
        actions.addWidget(self.cancel)
        actions.addStretch()
        layout.addLayout(actions)
        self.progress_label = QLabel("Ready · Select a workspace and evidence source")
        self.progress_label.setWordWrap(True)
        layout.addWidget(self.progress_label)
        self.progress = QProgressBar()
        self.progress.setAccessibleName("Evidence intake progress")
        self.progress.setValue(0)
        layout.addWidget(self.progress)
        self.result = QTextEdit()
        self.result.setReadOnly(True)
        self.result.setAccessibleName("Evidence registration result")
        self.result.setPlaceholderText("Verified evidence details and SHA-256 will appear here.")
        self.result.setMinimumHeight(160)
        layout.addWidget(self.result)
        note = QLabel(
            "Registration does not run Volatility or correlation. "
            "Format and plugin compatibility are checked during analysis."
        )
        note.setObjectName("muted")
        note.setWordWrap(True)
        layout.addWidget(note)
        layout.addStretch()
        self.setWidget(content)
        self.mode.currentIndexChanged.connect(self._mode_changed)
        self.start.clicked.connect(self._start)
        self.cancel.clicked.connect(self._cancel)
        self._mode_changed()

    def _path_row(self, field: QLineEdit, directory: bool = False) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(field, 1)
        browse = QPushButton("Browse…")
        browse.clicked.connect(lambda: self._browse(field, directory))
        layout.addWidget(browse)
        return row

    def _tool_selected(self, index: int) -> None:
        self.custom_tool_row.setVisible(index == self.custom_tool_id)

    def _load_environment(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Load acquisition tool configuration",
            "",
            "Environment files (.env *.env);;All files (*)",
        )
        if not path:
            return
        try:
            load_environment_file(path)
        except (OSError, ValueError) as exc:
            self._failed(f"Could not load configuration: {exc}")
            return
        self.configured_tools = available_tools()
        for index, option in enumerate(self.configured_tools):
            card = self.tool_choices.button(index)
            card.setEnabled(option.available)
            card.description_label.setText(option.description)
            card.setToolTip(option.description)
        selected = next(
            (i for i, option in enumerate(self.configured_tools) if option.available),
            self.custom_tool_id,
        )
        self.tool_choices.button(selected).setChecked(True)
        self._tool_selected(selected)
        self.progress_label.setText(
            "Configuration loaded. Existing environment variables take precedence."
        )

    def _file_selected(self, text: str) -> None:
        try:
            path = Path(text).expanduser()
            if not text or not path.is_file():
                self.file_details.setText("Choose an existing local memory image.")
                return
            size = path.stat().st_size
            self.file_details.setText(
                f"{size:,} bytes · {size / 1024**3:.2f} GiB · read-only import"
            )
        except OSError as exc:
            self.file_details.setText(f"Cannot read file details: {exc}")

    def _browse(self, field: QLineEdit, directory: bool) -> None:
        if directory:
            path = QFileDialog.getExistingDirectory(self, "Choose workspace", field.text())
        else:
            path, _ = QFileDialog.getOpenFileName(self, "Choose file", field.text())
        if path:
            field.setText(path)
            if directory:
                self._load_cases()

    def _load_cases(self) -> None:
        if not self.workspace.text().strip():
            self._failed("Choose a workspace to load its cases.")
            return
        try:
            cases = IntakeService.list_cases(Path(self.workspace.text().strip()))
        except Exception as exc:
            self._failed(f"Could not load cases: {exc}")
            return
        self.existing_cases.clear()
        self.existing_cases.addItem("Create a new case", None)
        for case in cases:
            if case.status == "open":
                self.existing_cases.addItem(f"{case.case_number} · {case.name}", case)

    def _select_case(self) -> None:
        case = self.existing_cases.currentData()
        self.case_number.setReadOnly(case is not None)
        self.case_name.setReadOnly(case is not None)
        self.case_number.setText(case.case_number if case else "")
        self.case_name.setText(case.name if case else "")

    def _mode_changed(self) -> None:
        live = self.mode.currentIndex() == 1
        self.mode_buttons.button(self.mode.currentIndex()).setChecked(True)
        self.live_fields.setVisible(live)
        self.import_fields.setVisible(not live)
        self.start.setText("Capture and verify" if live else "Import and verify")
        self.mode_hint.setText(
            "Capture uses system authentication (Polkit / UAC). Only the tool is elevated. "
            "Cancellation waits for elevated capture to finish. Select a configured tool or browse "
            "for a compatible executable; arbitrary commands and other dump-tool formats are not supported."
            if live
            else "The original image stays in its current location and is opened read-only. "
            "Two SHA-256 passes establish and verify its baseline."
        )

    @property
    def busy(self) -> bool:
        return self.worker is not None and self.worker.isRunning()

    def _start(self) -> None:
        if self.busy:
            return
        live = self.mode.currentIndex() == 1
        if not all(
            field.text().strip() for field in (self.workspace, self.case_number, self.case_name)
        ):
            self._failed("Enter a workspace, case number, and case name.")
            return
        if live and not self.authorized.isChecked():
            self._failed("Confirm authorization before capturing live memory.")
            return
        if not live and not self.source.text().strip():
            self._failed("Select a memory image to import.")
            return
        tool_path = None
        if live:
            tool_index = self.tool_choices.checkedId()
            if tool_index == self.custom_tool_id:
                if not self.tool.text().strip():
                    self._failed("Choose a compatible acquisition executable first.")
                    return
                tool_path = Path(self.tool.text().strip()).expanduser()
            elif 0 <= tool_index < len(self.configured_tools):
                tool_path = self.configured_tools[tool_index].path
            if tool_path is None or not tool_path.is_file():
                self._failed("The selected tool is unavailable. Check its configured path.")
                return
        os_values = [None, EvidenceOS.WINDOWS, EvidenceOS.LINUX, EvidenceOS.MACOS]
        request = IntakeRequest(
            workspace=Path(self.workspace.text().strip()),
            case_number=self.case_number.text().strip(),
            case_name=self.case_name.text().strip(),
            source=None if live else Path(self.source.text().strip()),
            evidence_os=os_values[self.os_choice.currentIndex()],
            tool_path=tool_path,
            avml_modern=self.profile.currentIndex() == 1,
        )
        self.settings.setValue("intake/workspace", str(request.workspace))
        self.settings.setValue("intake/tool", self.tool.text().strip())
        self.result.clear()
        self.form.setEnabled(False)
        self.start.setEnabled(False)
        self.cancel.setEnabled(True)
        self._progress("Preparing evidence intake", -1)
        self.worker = IntakeWorker(request, self)
        self.worker.progress.connect(self._progress)
        self.worker.succeeded.connect(self._succeeded)
        self.worker.failed.connect(self._failed)
        self.worker.finished.connect(self._finished)
        self.worker.start()

    def _progress(self, message: str, value: int) -> None:
        self.progress_label.setText(message)
        self.progress.setRange(0, 0 if value < 0 else 100)
        if value >= 0:
            self.progress.setValue(value)
        self.status_changed.emit(message + (f" · {value}%" if value >= 0 else ""))

    def _succeeded(self, result) -> None:
        evidence = result.evidence
        self.result.setPlainText(
            f"✓ Evidence verified and registered\n\nFile: {evidence.file_path}\n"
            f"Size: {evidence.file_size_bytes:,} bytes\nSHA-256: {evidence.sha256}\n"
            f"Evidence ID: {evidence.id}\nDatabase: {result.database_path}\nAudit: {result.audit_path}"
        )
        self.evidence_registered.emit(result)

    def _failed(self, message: str) -> None:
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress_label.setText(message)
        self.result.setPlainText(message)
        self.status_changed.emit(message)

    def _finished(self) -> None:
        self.form.setEnabled(True)
        self.start.setEnabled(True)
        self.cancel.setEnabled(False)
        self.worker.deleteLater()
        self.worker = None

    def _cancel(self) -> None:
        if self.busy:
            self.worker.cancelled.set()
            self.cancel.setEnabled(False)
            self.progress_label.setText(
                "Cancellation requested. Dismiss any authentication prompt. "
                "An elevated capture already in progress must finish first."
            )
