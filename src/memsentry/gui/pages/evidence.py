"""Memory-image import and live acquisition backed by the intake service."""

from pathlib import Path
from threading import Event

from PySide6.QtCore import QSettings, QThread, Signal
from PySide6.QtWidgets import (
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

from memsentry.app.intake_service import IntakeRequest, IntakeService
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
        self.mode = QComboBox()
        self.mode.addItems(["Import memory image", "Live memory acquisition"])
        self.mode.setAccessibleName("Evidence source")
        form_layout.addWidget(self.mode)
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
        form_layout.addLayout(form)

        self.import_fields = QWidget()
        import_form = QFormLayout(self.import_fields)
        import_form.setContentsMargins(0, 0, 0, 0)
        import_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.source = QLineEdit()
        self.source.setPlaceholderText("Select a .raw, .mem, .lime, or other memory image")
        import_form.addRow("Memory image", self._path_row(self.source))
        self.os_choice = QComboBox()
        self.os_choice.addItems(["Unknown / identify during analysis", "Windows", "Linux", "macOS"])
        import_form.addRow("Image OS", self.os_choice)
        form_layout.addWidget(self.import_fields)

        self.live_fields = QWidget()
        live_form = QFormLayout(self.live_fields)
        live_form.setContentsMargins(0, 0, 0, 0)
        live_form.setRowWrapPolicy(QFormLayout.RowWrapPolicy.WrapLongRows)
        self.tool = QLineEdit(str(self.settings.value("intake/tool", "")))
        self.tool.setPlaceholderText("Optional: uses MEMSENTRY_AVML / MEMSENTRY_WINPMEM or PATH")
        live_form.addRow("Dump tool", self._path_row(self.tool))
        self.profile = QComboBox()
        self.profile.addItems(
            ["AVML legacy: avml output.lime", "AVML current: avml acquire output.lime"]
        )
        live_form.addRow("Linux CLI", self.profile)
        self.authorized = QCheckBox("I am authorized to capture memory on this host.")
        live_form.addRow(self.authorized)
        form_layout.addWidget(self.live_fields)
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
        self.live_fields.setVisible(live)
        self.import_fields.setVisible(not live)
        self.start.setText("Capture and verify" if live else "Import and verify")
        self.mode_hint.setText(
            "Live capture uses AVML on Linux or WinPmem mini on Windows and requires root / "
            "Administrator privileges. Capture affects live RAM. Partial captures and tool logs "
            "are retained on failure. macOS capture is not enabled."
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
        os_values = [None, EvidenceOS.WINDOWS, EvidenceOS.LINUX, EvidenceOS.MACOS]
        request = IntakeRequest(
            workspace=Path(self.workspace.text().strip()),
            case_number=self.case_number.text().strip(),
            case_name=self.case_name.text().strip(),
            source=None if live else Path(self.source.text().strip()),
            evidence_os=os_values[self.os_choice.currentIndex()],
            tool_path=Path(self.tool.text().strip()) if self.tool.text().strip() else None,
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
            self.progress_label.setText("Cancelling safely…")
