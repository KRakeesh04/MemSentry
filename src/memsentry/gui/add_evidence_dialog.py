"""Dialog for selecting, inspecting, and registering forensic RAM evidence."""

from __future__ import annotations

from pathlib import Path
from uuid import UUID

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtGui import QCloseEvent, QDragEnterEvent, QDropEvent
from PySide6.QtWidgets import (
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QRadioButton,
    QVBoxLayout,
    QWidget,
)

from memsentry.gui.theme import MEMSENTRY_QSS, create_card_frame
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


class DropZoneFrame(QFrame):
    """Drag & drop target frame for memory dump files."""

    file_dropped = Signal(Path)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Sunken)
        self.setStyleSheet(
            "QFrame { background-color: #0F172A; border: 2px dashed #334155; border-radius: 10px; padding: 20px; }"
            "QFrame:hover { border-color: #3B82F6; background-color: #1E293B; }"
        )

    def dragEnterEvent(self, event: QDragEnterEvent) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent) -> None:
        for url in event.mimeData().urls():
            file_path = Path(url.toLocalFile())
            if file_path.is_file():
                self.file_dropped.emit(file_path)
                break


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
        self.resize(620, 580)
        self.setStyleSheet(MEMSENTRY_QSS)

        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(16)

        # Title & Header
        header_title = QLabel("Evidence Acquisition & Dump Registration")
        header_title.setObjectName("dialogTitle")
        header_title.setStyleSheet("color: #F8FAFC; font-size: 20px; font-weight: 800;")

        subtitle_label = QLabel(
            "Select an offline memory dump (.raw, .dmp, .vmem), compute SHA-256 hash, and assign OS profile."
        )
        subtitle_label.setStyleSheet("color: #94A3B8; font-size: 12px;")

        layout.addWidget(header_title)
        layout.addWidget(subtitle_label)

        # Acquisition Method Card (Figma Design Compliance)
        acquisition_card = create_card_frame()
        acq_layout = QVBoxLayout(acquisition_card)
        acq_layout.setContentsMargins(16, 14, 16, 14)
        acq_layout.setSpacing(8)

        acq_title = QLabel("ACQUISITION SOURCE")
        acq_title.setStyleSheet("color: #64748B; font-size: 10px; font-weight: 800; letter-spacing: 0.5px;")
        acq_layout.addWidget(acq_title)

        radios_box = QHBoxLayout()
        self.offline_radio = QRadioButton("Offline Memory Dump (Supported)")
        self.offline_radio.setChecked(True)
        self.offline_radio.setStyleSheet("color: #F8FAFC; font-size: 12px; font-weight: 600;")

        self.live_radio = QRadioButton("Live RAM Capture (Unavailable)")
        self.live_radio.setEnabled(False)
        self.live_radio.setToolTip(
            "MemSentry analyzes previously acquired offline memory dumps."
        )
        self.live_radio.setStyleSheet("color: #64748B; font-size: 12px;")

        radios_box.addWidget(self.offline_radio)
        radios_box.addWidget(self.live_radio)
        radios_box.addStretch()
        acq_layout.addLayout(radios_box)

        live_note_label = QLabel(
            "Note: Live RAM acquisition is unavailable. MemSentry analyzes offline memory images."
        )
        live_note_label.setObjectName("acquisitionNote")
        live_note_label.setStyleSheet("color: #64748B; font-size: 11px;")
        acq_layout.addWidget(live_note_label)

        layout.addWidget(acquisition_card)

        # Drag and Drop File Picker Card
        self.drop_zone = DropZoneFrame()
        self.drop_zone.file_dropped.connect(self.set_file_path)

        dz_layout = QVBoxLayout(self.drop_zone)
        dz_layout.setSpacing(8)

        dz_icon = QLabel("📁  Drag & Drop Memory Dump File Here")
        dz_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dz_icon.setStyleSheet("color: #3B82F6; font-size: 14px; font-weight: 700;")

        dz_sub = QLabel("Supported formats: .raw, .dmp, .vmem, .mem, .lime, .bin (up to 128 GB)")
        dz_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dz_sub.setStyleSheet("color: #64748B; font-size: 11px;")

        # File Input & Browse Button
        file_picker_layout = QHBoxLayout()
        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("No memory image file selected")
        self.file_path_input.setReadOnly(True)
        self.file_path_input.setStyleSheet(
            "background-color: #020617; border: 1px solid #1E293B; border-radius: 6px; padding: 6px 12px; color: #94A3B8;"
        )

        self.browse_button = QPushButton("Browse File...")
        self.browse_button.setObjectName("secondaryButton")
        self.browse_button.setStyleSheet(
            "background-color: #1E293B; color: #F8FAFC; border: 1px solid #334155; border-radius: 6px; padding: 6px 14px; font-weight: 600;"
        )
        self.browse_button.clicked.connect(self.browse_file)

        file_picker_layout.addWidget(self.file_path_input, stretch=1)
        file_picker_layout.addWidget(self.browse_button)

        dz_layout.addWidget(dz_icon)
        dz_layout.addWidget(dz_sub)
        dz_layout.addLayout(file_picker_layout)

        layout.addWidget(self.drop_zone)

        # File Metadata & Hash Verification Card
        meta_card = create_card_frame()
        meta_layout = QVBoxLayout(meta_card)
        meta_layout.setContentsMargins(16, 14, 16, 14)
        meta_layout.setSpacing(10)

        row1 = QHBoxLayout()
        r1_name_lbl = QLabel("Original Filename:")
        r1_name_lbl.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 700;")
        self.filename_label = QLabel("N/A")
        self.filename_label.setStyleSheet("color: #F8FAFC; font-size: 12px; font-weight: 700;")

        r1_size_lbl = QLabel("File Size:")
        r1_size_lbl.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 700; margin-left: 20px;")
        self.filesize_label = QLabel("N/A")
        self.filesize_label.setStyleSheet("color: #F8FAFC; font-size: 12px; font-weight: 700;")

        row1.addWidget(r1_name_lbl)
        row1.addWidget(self.filename_label)
        row1.addStretch()
        row1.addWidget(r1_size_lbl)
        row1.addWidget(self.filesize_label)
        meta_layout.addLayout(row1)

        # SHA-256 Box
        hash_header = QHBoxLayout()
        hash_lbl = QLabel("SHA-256 Cryptographic Hash:")
        hash_lbl.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 700;")

        self.hash_status_label = QLabel("")
        self.hash_status_label.setStyleSheet("font-size: 11px; color: #3B82F6; font-weight: 600;")

        hash_header.addWidget(hash_lbl)
        hash_header.addStretch()
        hash_header.addWidget(self.hash_status_label)
        meta_layout.addLayout(hash_header)

        self.sha256_display = QLineEdit()
        self.sha256_display.setPlaceholderText("SHA-256 hash will be calculated automatically upon file selection")
        self.sha256_display.setReadOnly(True)
        self.sha256_display.setStyleSheet(
            "font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; color: #60A5FA; background-color: #020617; border: 1px solid #1E293B; padding: 6px 10px; border-radius: 6px;"
        )
        meta_layout.addWidget(self.sha256_display)

        # Target OS Combo
        os_row = QHBoxLayout()
        os_lbl = QLabel("Target OS Profile:")
        os_lbl.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 700;")

        self.os_combo = QComboBox()
        self.os_combo.addItem("Windows Target Profile", EvidenceOS.WINDOWS)
        self.os_combo.addItem("Linux Target Profile", EvidenceOS.LINUX)
        self.os_combo.addItem("macOS Target Profile", EvidenceOS.MACOS)
        self.os_combo.addItem("Auto Detect / Unknown", None)
        self.os_combo.setStyleSheet(
            "background-color: #020617; border: 1px solid #1E293B; border-radius: 6px; padding: 6px 12px; color: #F8FAFC;"
        )

        os_row.addWidget(os_lbl)
        os_row.addWidget(self.os_combo, stretch=1)
        meta_layout.addLayout(os_row)

        layout.addWidget(meta_card)

        # Form Error Display
        self.error_label = QLabel()
        self.error_label.setObjectName("formError")
        self.error_label.setWordWrap(True)
        self.error_label.setStyleSheet("color: #EF4444; font-size: 11px; font-weight: 600;")
        layout.addWidget(self.error_label)

        # Dialog Action Buttons
        self.buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Cancel)
        self.register_button = QPushButton("Register Evidence File")
        self.register_button.setObjectName("primaryButton")
        self.register_button.setEnabled(False)
        self.register_button.setStyleSheet(
            "background-color: #2563EB; color: #FFFFFF; border: none; border-radius: 6px; padding: 8px 20px; font-weight: 700;"
        )

        self.buttons.addButton(
            self.register_button, QDialogButtonBox.ButtonRole.AcceptRole
        )
        self.buttons.accepted.connect(self.register_evidence)
        self.buttons.rejected.connect(self.reject)

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
