"""Dialog for selecting and registering forensic RAM evidence."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from PySide6.QtCore import QObject, QThread, Signal
from PySide6.QtGui import QCloseEvent
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from memsentry.models.evidence import EvidenceCreate, EvidenceOS
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.utils.hashing import compute_file_sha256


class HashWorker(QThread):
    """Background worker thread for SHA-256 calculation on large memory dumps."""

    finished = Signal(str)
    failed = Signal(str)

    def __init__(self, file_path: Path, parent: QObject | None = None) -> None:
        super().__init__(parent)
        self.file_path = file_path

    def run(self) -> None:
        try:
            digest = compute_file_sha256(self.file_path)
            self.finished.emit(digest)
        except Exception as exc:
            self.failed.emit(str(exc))


class AddEvidenceDialog(QDialog):
    """Collect RAM dump metadata and register evidence through EvidenceRepository."""

    evidence_created = Signal(object)

    SUPPORTED_FILTERS = (
        "Memory Images (*.raw *.dmp *.vmem *.mem *.lime *.bin);;All Files (*)"
    )

    def __init__(
        self,
        case_id: UUID,
        evidence_repository: EvidenceRepository,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.case_id = case_id
        self.evidence_repository = evidence_repository
        self.selected_path: Path | None = None
        self.hash_worker: HashWorker | None = None

        self.setWindowTitle("Register Evidence")
        self.setModal(True)
        self.resize(560, 480)

        self._build_ui()

    def _build_ui(self) -> None:
        # Title & Description
        header_label = QLabel("Register Forensic Evidence")
        header_label.setObjectName("dialogTitle")
        subtitle_label = QLabel(
            "Select an offline memory image to register for analysis."
        )

        # Acquisition Method Group (Figma Design Compliance)
        acquisition_group = QGroupBox("Acquisition Source")
        acq_layout = QVBoxLayout(acquisition_group)

        self.offline_radio = QRadioButton("Offline Memory Dump (Supported)")
        self.offline_radio.setChecked(True)

        self.live_radio = QRadioButton("Live RAM Acquisition (Unavailable)")
        self.live_radio.setEnabled(False)
        self.live_radio.setToolTip(
            "MemSentry analyzes previously acquired offline memory dumps."
        )

        live_note_label = QLabel(
            "Note: Live RAM acquisition is unavailable. MemSentry analyzes offline memory images."
        )
        live_note_label.setObjectName("acquisitionNote")
        live_note_label.setStyleSheet("color: #718096; font-size: 11px;")

        acq_layout.addWidget(self.offline_radio)
        acq_layout.addWidget(self.live_radio)
        acq_layout.addWidget(live_note_label)

        # File Selection Form
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("No memory image selected")
        self.file_path_input.setReadOnly(True)

        self.browse_button = QPushButton("Browse...")
        self.browse_button.clicked.connect(self.browse_file)

        file_picker_layout = QHBoxLayout()
        file_picker_layout.addWidget(self.file_path_input)
        file_picker_layout.addWidget(self.browse_button)

        self.filename_label = QLabel("N/A")
        self.filesize_label = QLabel("N/A")

        self.sha256_display = QLineEdit()
        self.sha256_display.setPlaceholderText("SHA-256 hash will be calculated")
        self.sha256_display.setReadOnly(True)

        self.hash_status_label = QLabel("")
        self.hash_status_label.setStyleSheet("font-size: 12px; color: #4A5568;")

        # Target OS Combo
        self.os_combo = QComboBox()
        self.os_combo.addItem("Windows", EvidenceOS.WINDOWS)
        self.os_combo.addItem("Linux", EvidenceOS.LINUX)
        self.os_combo.addItem("macOS", EvidenceOS.MACOS)
        self.os_combo.addItem("Auto / Unknown", None)

        form = QFormLayout()
        form.addRow("Memory Image File", file_picker_layout)
        form.addRow("Original Filename", self.filename_label)
        form.addRow("File Size", self.filesize_label)
        form.addRow("SHA-256 Hash", self.sha256_display)
        form.addRow("Hash Status", self.hash_status_label)
        form.addRow("Target OS", self.os_combo)

        # Form Error Display
        self.error_label = QLabel()
        self.error_label.setObjectName("formError")
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet("color: #E53E3E;")

        # Dialog Action Buttons
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.register_button = QPushButton("Register Evidence")
        self.register_button.setEnabled(False)
        self.buttons.addButton(
            self.register_button, QDialogButtonBox.ButtonRole.AcceptRole
        )
        self.buttons.accepted.connect(self.register_evidence)
        self.buttons.rejected.connect(self.reject)

        # Main Layout
        layout = QVBoxLayout(self)
        layout.addWidget(header_label)
        layout.addWidget(subtitle_label)
        layout.addWidget(acquisition_group)
        layout.addLayout(form)
        layout.addWidget(self.error_label)
        layout.addWidget(self.buttons)

    def browse_file(self) -> None:
        """Open file dialog to select a memory image file."""
        file_path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Select Memory Dump File",
            "",
            self.SUPPORTED_FILTERS,
        )
        if file_path_str:
            self.set_file_path(Path(file_path_str))

    def set_file_path(self, path: Path) -> None:
        """Set the selected memory image file path and trigger SHA-256 computation."""
        self._cancel_hash_worker()
        self.error_label.clear()
        self.selected_path = path

        if not path.exists() or not path.is_file():
            self.file_path_input.setText(str(path))
            self.filename_label.setText(path.name if path.name else "N/A")
            self.filesize_label.setText("N/A")
            self.sha256_display.clear()
            self.hash_status_label.setText("Selected file does not exist")
            self.register_button.setEnabled(False)
            self.show_error("Selected file does not exist or is not a valid file.")
            return

        size_bytes = path.stat().st_size
        self.file_path_input.setText(str(path))
        self.filename_label.setText(path.name)
        self.filesize_label.setText(f"{size_bytes:,} bytes")
        self.sha256_display.clear()
        self.hash_status_label.setText("Calculating SHA-256...")
        self.register_button.setEnabled(False)

        self._start_hash_calculation(path)

    def _start_hash_calculation(self, path: Path) -> None:
        self.hash_worker = HashWorker(path, self)
        self.hash_worker.finished.connect(self._on_hash_finished)
        self.hash_worker.failed.connect(self._on_hash_failed)
        self.hash_worker.start()

    def _on_hash_finished(self, digest: str) -> None:
        self.sha256_display.setText(digest)
        self.hash_status_label.setText("SHA-256 verified")
        self.register_button.setEnabled(True)

    def _on_hash_failed(self, error_msg: str) -> None:
        self.sha256_display.clear()
        self.hash_status_label.setText("Hashing failed")
        self.register_button.setEnabled(False)
        self.show_error(f"Failed to calculate SHA-256 hash: {error_msg}")

    def _cancel_hash_worker(self) -> None:
        if self.hash_worker is not None and self.hash_worker.isRunning():
            self.hash_worker.requestInterruption()
            self.hash_worker.wait(1000)
            self.hash_worker = None

    def register_evidence(self) -> None:
        """Validate form and register evidence via EvidenceRepository."""
        if not self.selected_path or not self.selected_path.is_file():
            self.show_error("Please select a valid memory dump file.")
            return

        sha256_val = self.sha256_display.text().strip()
        if not sha256_val:
            self.show_error("SHA-256 hash calculation is not completed.")
            return

        selected_os: EvidenceOS | None = self.os_combo.currentData()

        try:
            file_size_bytes = self.selected_path.stat().st_size
            evidence_data = EvidenceCreate(
                case_id=self.case_id,
                original_filename=self.selected_path.name,
                file_path=self.selected_path,
                file_size_bytes=file_size_bytes,
                sha256=sha256_val,
                evidence_os=selected_os,
            )
            evidence = self.evidence_repository.create(evidence_data)
        except Exception as exc:
            self.show_error(f"Could not register evidence: {exc}")
            return

        self.evidence_created.emit(evidence)
        self.accept()

    def show_error(self, message: str) -> None:
        self.error_label.setText(message)

    def closeEvent(self, event: QCloseEvent) -> None:
        self._cancel_hash_worker()
        super().closeEvent(event)
