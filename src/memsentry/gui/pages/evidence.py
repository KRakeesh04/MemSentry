"""Memory-image import and live acquisition backed by the intake service."""

import platform
from pathlib import Path
from threading import Event

from PySide6.QtCore import QObject, QSettings, Qt, QThread, Signal
from PySide6.QtWidgets import (
    QButtonGroup,
    QCheckBox,
    QFileDialog,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLayout,
    QLineEdit,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSpacerItem,
    QVBoxLayout,
    QWidget,
)

from memsentry.acquisition.tool_catalog import available_tools
from memsentry.app.case_service import generate_case_number
from memsentry.app.intake_service import IntakeRequest, IntakeResult, IntakeService
from memsentry.gui.acquisition_settings import import_tool_settings, restore_tool_settings
from memsentry.gui.controls import ThemedComboBox
from memsentry.gui.intake_widgets import ChoiceCard, FileDropArea, SystemCard
from memsentry.models.case import Case
from memsentry.models.evidence import EvidenceOS


class IntakeWorker(QThread):
    progress = Signal(str, int)
    succeeded = Signal(object)
    failed = Signal(str)

    def __init__(self, request: IntakeRequest, parent: QObject | None = None, service: IntakeService | None = None) -> None:
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
    tool_configuration_changed = Signal()
    status_changed = Signal(str)
    evidence_registered = Signal(object)
    analyze_requested = Signal(object)
    intake_progress = Signal(str, int)
    intake_finished = Signal()
    intake_failed = Signal(str)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.worker: IntakeWorker | None = None
        self.registered_result: IntakeResult | None = None
        self.setAccessibleName("Memory evidence intake")
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)
        self.settings = QSettings("MemSentry", "MemSentry")
        restore_tool_settings()
        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setSizeConstraint(QLayout.SizeConstraint.SetMinAndMaxSize)
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
        self.form.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        self.form.setObjectName("card")

        form_layout = QVBoxLayout(self.form)
        form_layout.setContentsMargins(24, 24, 24, 24)
        form_layout.setSpacing(16)

        self.mode = ThemedComboBox(self.form)
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
        self.case_number = QLineEdit(generate_case_number())
        self.case_number.setToolTip("Suggested automatically; you can enter your own case number.")
        self.case_number.setPlaceholderText("e.g. CASE-2026-001")
        self.case_name = QLineEdit()
        self.case_name.setPlaceholderText("New case name, or the exact name of an existing case")
        form.addRow("Workspace", self._path_row(self.workspace, directory=True))

        case_row = QWidget()
        case_layout = QHBoxLayout(case_row)
        case_layout.setContentsMargins(0, 0, 0, 0)
        self.existing_cases = ThemedComboBox()
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
        self.drop_area.setMinimumHeight(120)
        self.drop_area.setMaximumHeight(140)
        self.drop_area.clicked.connect(lambda: self._browse(self.source, False))
        self.drop_area.file_selected.connect(self.source.setText)
        self.drop_area.invalid_drop.connect(self._failed)
        import_form.addRow(self.drop_area)
        import_form.addRow("Selected image", self._path_row(self.source))

        self.file_details = QLabel("No memory image selected.")
        self.file_details.setObjectName("muted")
        self.file_details.setWordWrap(True)
        self.source.textChanged.connect(self._file_selected)
        import_form.addRow(self.file_details)
        self.os_choice = ThemedComboBox()
        self.os_choice.addItems(["Unknown / identify during analysis", "Windows", "Linux", "macOS"])
        import_form.addRow("Image OS", self.os_choice)
        form_layout.addWidget(self.import_fields)

        self.live_fields = QWidget()
        self.live_fields.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        live_form = QVBoxLayout(self.live_fields)
        live_form.setAlignment(Qt.AlignmentFlag.AlignTop)
        live_form.setContentsMargins(0, 0, 0, 0)
        system_card = SystemCard()
        system_card.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Fixed)
        live_form.addWidget(system_card)

        live_form.addItem(QSpacerItem(
            0,
            10,
            QSizePolicy.Policy.Minimum,
            QSizePolicy.Policy.Fixed,
        ))

        tool_header = QWidget()
        tool_header_layout = QHBoxLayout(tool_header)
        tool_header_layout.setContentsMargins(0, 0, 0, 0)

        tool_title = QLabel("Acquisition tool")
        tool_title.setObjectName("sectionTitle")
        tool_header_layout.addWidget(tool_title)

        tool_header_layout.addStretch()

        load_env = QPushButton("Load configuration…")
        load_env.setToolTip(
            "Load acquisition tool paths from an environment configuration file."
        )
        load_env.clicked.connect(self._load_environment)
        tool_header_layout.addWidget(load_env)

        live_form.addWidget(tool_header)

        live_form.setSpacing(10)

        self.tool_choices = QButtonGroup(self)
        self.configured_tools = available_tools()
        for index, option in enumerate(self.configured_tools):
            card = ChoiceCard(f"{option.name} · {option.host}", option.description)
            card.setEnabled(option.available)
            card.setToolTip(option.description)
            self.tool_choices.addButton(card, index)
            live_form.addWidget(card)
        custom = ChoiceCard(
            "Choose another executable", "Browse for AVML on Linux or WinPmem mini on Windows"
        )
        custom.setEnabled(platform.system() in ("Linux", "Windows"))
        self.custom_tool_id = len(self.configured_tools)
        self.tool_choices.addButton(custom, self.custom_tool_id)
        live_form.addWidget(custom)
        self.tool = QLineEdit(str(self.settings.value("intake/tool", "")))
        self.tool.setPlaceholderText("Optional: uses MEMSENTRY_AVML / MEMSENTRY_WINPMEM or PATH")
        self.custom_tool_row = self._path_row(self.tool)
        live_form.addWidget(self.custom_tool_row)
        self.tool.setPlaceholderText("Path to a compatible acquisition executable")
        self.tool_choices.idClicked.connect(self._tool_selected)
        selected = next(
            (i for i, option in enumerate(self.configured_tools) if option.available),
            self.custom_tool_id,
        )
        self.tool_choices.button(selected).setChecked(True)
        self._tool_selected(selected)
        self.profile = ThemedComboBox()
        self.profile.addItems(
            [
                "Current AVML",
                "Legacy AVML",
            ]
        )
        self.profile.setCurrentIndex(0)
        self.profile.setToolTip(
            "Use Current AVML for modern releases. "
            "Choose Legacy AVML only for older AVML binaries."
        )
        if platform.system() == "Linux":
            profile_form = QFormLayout()
            profile_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
            profile_form.addRow("AVML version", self.profile)
            live_form.addLayout(profile_form)
        else:
            self.profile.setParent(self.live_fields)
            self.profile.hide()
        self.authorized = QCheckBox("I am authorized to capture memory on this host.")

        form_layout.addWidget(self.live_fields)

        self.case_section = QWidget()

        case_section_layout = QVBoxLayout(self.case_section)
        case_section_layout.setContentsMargins(0, 0, 0, 0)
        case_section_layout.setSpacing(12)

        case_heading = QLabel("Case & storage")
        case_heading.setObjectName("sectionTitle")
        case_section_layout.addWidget(case_heading)

        case_section_layout.addLayout(form)

        form_layout.addWidget(self.case_section)

        self.active_case_card = QFrame()
        self.active_case_card.setObjectName("card")
        self.active_case_card.hide()

        active_case_layout = QVBoxLayout(self.active_case_card)
        active_case_layout.setContentsMargins(16, 12, 16, 12)
        active_case_layout.setSpacing(4)

        self.active_case_title = QLabel()
        self.active_case_title.setObjectName("sectionTitle")

        self.active_case_details = QLabel()
        self.active_case_details.setObjectName("muted")

        active_case_layout.addWidget(self.active_case_title)
        active_case_layout.addWidget(self.active_case_details)

        form_layout.addWidget(self.active_case_card)

        layout.addWidget(self.form)

        self.authorization_row = QWidget()
        authorization_layout = QHBoxLayout(self.authorization_row)
        authorization_layout.setContentsMargins(0, 0, 0, 0)

        authorization_layout.addWidget(self.authorized)
        authorization_layout.addStretch()

        layout.addWidget(self.authorization_row)

        actions = QHBoxLayout()
        self.start = QPushButton("Import and verify")
        self.start.setObjectName("primaryAction")
        self.cancel = QPushButton("Cancel")
        self.cancel.setEnabled(False)
        self.analyse = QPushButton("Analyse evidence")
        self.analyse.setHidden(True)
        actions.addWidget(self.start)
        actions.addWidget(self.cancel)
        actions.addWidget(self.analyse)
        actions.addStretch()
        layout.addLayout(actions)
        self.progress_label = QLabel("Ready · Select a workspace and evidence source")
        self.progress_label.setWordWrap(True)
        layout.addWidget(self.progress_label)
        self.progress = QProgressBar()
        self.progress.setAccessibleName("Evidence intake progress")
        self.progress.setValue(0)
        layout.addWidget(self.progress)
        self.progress.hide()

        self.result_card = QFrame()
        self.result_card.setObjectName("successCard")
        self.result_card.hide()

        result_layout = QVBoxLayout(self.result_card)
        result_layout.setContentsMargins(16, 12, 16, 12)
        result_layout.setSpacing(6)

        self.result = QPlainTextEdit()
        self.result.setReadOnly(True)
        self.result.setMaximumHeight(112)
        self.result.setAccessibleName("Evidence intake result")
        result_layout.addWidget(self.result)

        layout.addWidget(self.result_card)
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
        self.analyse.clicked.connect(self._start_analysis)
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
            import_tool_settings(path)
        except (OSError, ValueError) as exc:
            self._failed(f"Could not load configuration: {exc}")
            return
        self.refresh_tools()
        self.tool_configuration_changed.emit()
        self.progress_label.setText("Configuration loaded and saved.")

    def refresh_tools(self) -> None:
        self.configured_tools = available_tools()
        for index, option in enumerate(self.configured_tools):
            card = self.tool_choices.button(index)
            if not isinstance(card, ChoiceCard):
                continue
            card.setEnabled(option.available)
            card.description_label.setText(option.description)
            card.setToolTip(option.description)
        selected = next(
            (i for i, option in enumerate(self.configured_tools) if option.available),
            self.custom_tool_id,
        )
        self.tool_choices.button(selected).setChecked(True)
        self._tool_selected(selected)

    def _file_selected(self, text: str) -> None:
        try:
            path = Path(text).expanduser()
            if not text or not path.is_file():
                self.file_details.setText("Choose an existing local memory image.")
                return
            size = path.stat().st_size
            size_description = (
                f"{size} bytes" if size < 1024**2 else f"{size / 1024**3:.2f} GiB"
            )
            self.file_details.setText(
                f"{path.name} · {size_description} · read-only import"
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

    def _load_cases(self) -> bool:
        if not self.workspace.text().strip():
            self._failed("Choose a workspace to load its cases.")
            return False
        try:
            cases = IntakeService.list_cases(Path(self.workspace.text().strip()))
        except Exception as exc:
            self._failed(f"Could not load cases: {exc}")
            return False
        selected = self.existing_cases.currentData()
        number, name = self.case_number.text(), self.case_name.text()
        self.existing_cases.blockSignals(True)
        self.existing_cases.clear()
        self.existing_cases.addItem("Create a new case", None)
        for case in cases:
            if case.status == "open":
                self.existing_cases.addItem(f"{case.case_number} · {case.name}", case)
                if selected and selected.id == case.id:
                    self.existing_cases.setCurrentIndex(self.existing_cases.count() - 1)
        self.existing_cases.blockSignals(False)
        self._select_case()

        if selected is None:
            self.case_number.setText(number or generate_case_number())
            self.case_name.setText(name)
        return True

    def use_case(self, workspace: str, case: Case) -> bool:
        """Select an existing open case without altering an active intake job."""
        if self.busy:
            return False
        self.workspace.setText(workspace)
        if not self._load_cases():
            return False
        for index in range(1, self.existing_cases.count()):
            if self.existing_cases.itemData(index).id == case.id:
                self.existing_cases.setCurrentIndex(index)
                self._select_case()

                self.case_section.hide()
                self.active_case_card.show()

                self.active_case_title.setText(case.name)
                self.active_case_details.setText(
                    f"{case.case_number} · {case.status.title()}"
                )
                return True
        self._failed("This case is no longer open or available. Refresh the case overview.")
        return False

    def _select_case(self) -> None:
        case = self.existing_cases.currentData()
        self.case_number.setReadOnly(case is not None)
        self.case_name.setReadOnly(case is not None)
        self.case_number.setText(case.case_number if case else generate_case_number())
        self.case_name.setText(case.name if case else "")

    def _mode_changed(self) -> None:
        live = self.mode.currentIndex() == 1
        self.authorization_row.setVisible(live)
        self.mode_buttons.button(self.mode.currentIndex()).setChecked(True)
        self.live_fields.setVisible(live)
        self.import_fields.setVisible(not live)
        self.start.setText("Capture and verify" if live else "Import and verify")
        self.mode_hint.setText(
                "Live capture uses system authentication. "
                "Only the acquisition tool is elevated. "
                "Cancellation may wait until the elevated capture finishes."
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
            avml_modern=self.profile.currentIndex() == 0,
        )
        self.settings.setValue("intake/workspace", str(request.workspace))
        self.settings.setValue("intake/tool", self.tool.text().strip())
        self.progress_label.show()
        self.progress.show()
        self.result_card.hide()
        self.result.clear()
        self.registered_result = None
        self.analyse.hide()
        self.analyse.setEnabled(False)
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
        self.progress.show()
        self.intake_progress.emit(message, value)
        self.progress_label.setText(message)
        self.progress.setRange(0, 0 if value < 0 else 100)
        if value >= 0:
            self.progress.setValue(value)
        self.status_changed.emit(message + (f" · {value}%" if value >= 0 else ""))

    def _succeeded(self, result: IntakeResult) -> None:
        self.registered_result = result
        evidence = result.evidence
        self.result_card.show()
        self.progress_label.hide()
        self.progress.hide()

        self.result.setPlainText(
            "Evidence verified and registered\n"
            f"{Path(evidence.file_path).name} · "
            f"{evidence.file_size_bytes / 1024**3:.2f} GiB\n"
            f"Audit: {result.audit_path}\n"
            f"SHA-256: {evidence.sha256}"
        )

        self.evidence_registered.emit(result)
        self.analyse.setHidden(False)
        self.analyse.setEnabled(self.worker is None)

    def _start_analysis(self) -> None:
        if self.registered_result is not None and not self.busy:
            self.analyze_requested.emit(self.registered_result)

    def _failed(self, message: str) -> None:
        if self.worker is not None:
            self.intake_failed.emit(message)
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress_label.setText(message)
        self.result.show()
        self.result.setPlainText(message)
        self.result_card.show()
        self.progress.hide()
        self.status_changed.emit(message)

    def _finished(self) -> None:
        self.form.setEnabled(True)
        self.start.setEnabled(True)
        self.cancel.setEnabled(False)
        if self.worker is not None:
            self.worker.deleteLater()
        self.worker = None
        self.analyse.setEnabled(self.registered_result is not None)
        self.intake_finished.emit()

    def _cancel(self) -> None:
        if self.busy and self.worker is not None:
            self.worker.cancelled.set()
            self.cancel.setEnabled(False)
            self.progress_label.setText(
                "Cancellation requested. Dismiss any authentication prompt. "
                "An elevated capture already in progress must finish first."
            )
