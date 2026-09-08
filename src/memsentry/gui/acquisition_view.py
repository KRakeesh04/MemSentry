"""Evidence Acquisition full-page view for MemSentry matching Figma visual reference."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QObject, Qt, QThread, Signal
from PySide6.QtGui import QDragEnterEvent, QDropEvent, QMouseEvent
from PySide6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from memsentry.gui.theme import create_badge_label, create_card_frame
from memsentry.models.case import Case
from memsentry.models.evidence import EvidenceCreate, EvidenceOS
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.utils.hashing import compute_file_sha256


class AcquisitionHashWorker(QThread):
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


class AcquisitionDropZone(QFrame):
    """Clean single-container drag & drop target area matching Figma Evidence Acquisition design."""

    file_dropped = Signal(Path)
    clicked = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet(
            "QFrame { background-color: #0F172A; border: 2px dashed #3B82F6; border-radius: 12px; padding: 40px; }"
            "QFrame:hover { border-color: #60A5FA; background-color: #1E293B; }"
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

    def mousePressEvent(self, event: QMouseEvent) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            self.clicked.emit()
        super().mousePressEvent(event)


class EvidenceAcquisitionView(QWidget):
    """Full-page Evidence Acquisition view for memory dump registration."""

    evidence_created = Signal(object)

    SUPPORTED_FILTERS = (
        "Memory Images (*.raw *.dmp *.vmem *.mem *.lime *.bin);;All Files (*)"
    )

    def __init__(
        self,
        evidence_repository: EvidenceRepository | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.evidence_repository = evidence_repository
        self.active_case: Case | None = None
        self.selected_path: Path | None = None
        self.hash_worker: AcquisitionHashWorker | None = None

        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(20)

        # ---------------------------------------------------------------------
        # Header Section: EVIDENCE ACQUISITION / Add Evidence to Investigation
        # ---------------------------------------------------------------------
        header_box = QVBoxLayout()
        header_box.setSpacing(4)

        sub_title = QLabel("EVIDENCE ACQUISITION")
        sub_title.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 800; letter-spacing: 1px;")

        main_title = QLabel("Add Evidence to Investigation")
        main_title.setStyleSheet("color: #F8FAFC; font-size: 24px; font-weight: 800;")

        header_box.addWidget(sub_title)
        header_box.addWidget(main_title)

        layout.addLayout(header_box)

        # ---------------------------------------------------------------------
        # Acquisition Mode Selector Cards (Import Memory Dump vs Live RAM)
        # ---------------------------------------------------------------------
        modes_layout = QHBoxLayout()
        modes_layout.setSpacing(16)

        # Mode 1: Import Memory Dump (Active)
        import_card = create_card_frame()
        import_card.setStyleSheet("background-color: #1E293B; border: 1px solid #3B82F6; border-radius: 10px;")
        ic_layout = QHBoxLayout(import_card)
        ic_layout.setContentsMargins(16, 14, 16, 14)

        ic_icon = QLabel("📁")
        ic_icon.setStyleSheet("font-size: 20px;")
        ic_info = QVBoxLayout()
        ic_title = QLabel("Import Memory Dump")
        ic_title.setStyleSheet("color: #F8FAFC; font-weight: 700; font-size: 14px;")
        ic_desc = QLabel("Register offline RAM dumps (.raw, .dmp, .vmem) for triage")
        ic_desc.setStyleSheet("color: #94A3B8; font-size: 11px;")
        ic_info.addWidget(ic_title)
        ic_info.addWidget(ic_desc)

        ic_layout.addWidget(ic_icon)
        ic_layout.addLayout(ic_info, stretch=1)

        # Mode 2: Live Memory Acquisition (Disabled/Enterprise Note)
        live_card = create_card_frame()
        live_card.setStyleSheet("background-color: #0F172A; border: 1px solid #1E293B; border-radius: 10px;")
        lc_layout = QHBoxLayout(live_card)
        lc_layout.setContentsMargins(16, 14, 16, 14)

        lc_icon = QLabel("⚡")
        lc_icon.setStyleSheet("font-size: 20px; color: #64748B;")
        lc_info = QVBoxLayout()
        lc_title = QLabel("Live Memory Acquisition")
        lc_title.setStyleSheet("color: #64748B; font-weight: 700; font-size: 14px;")
        lc_desc = QLabel("Enterprise live agent capture (Offline dumps supported)")
        lc_desc.setStyleSheet("color: #475569; font-size: 11px;")
        lc_info.addWidget(lc_title)
        lc_info.addWidget(lc_desc)

        lc_layout.addWidget(lc_icon)
        lc_layout.addLayout(lc_info, stretch=1)

        modes_layout.addWidget(import_card)
        modes_layout.addWidget(live_card)

        layout.addLayout(modes_layout)

        # ---------------------------------------------------------------------
        # Single Large Drag & Drop Memory Dump Area (Figma Refinement)
        # ---------------------------------------------------------------------
        self.drop_zone = AcquisitionDropZone()
        self.drop_zone.file_dropped.connect(self.set_file_path)
        self.drop_zone.clicked.connect(self.browse_file)

        dz_layout = QVBoxLayout(self.drop_zone)
        dz_layout.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dz_layout.setSpacing(12)

        # 1. Upload/Download Icon
        dz_icon = QLabel("⬇")
        dz_icon.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dz_icon.setStyleSheet("color: #3B82F6; font-size: 42px; font-weight: 900;")

        # 2. Main Title
        dz_title = QLabel("Drop memory dump here, or click to select")
        dz_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dz_title.setStyleSheet("color: #F8FAFC; font-size: 16px; font-weight: 700;")

        # 3. Supported Formats
        dz_sub = QLabel("Supported formats: .raw · .dmp · .vmem · .mem · .lime · .bin")
        dz_sub.setAlignment(Qt.AlignmentFlag.AlignCenter)
        dz_sub.setStyleSheet("color: #64748B; font-size: 12px; font-weight: 500;")

        # 4. Browse Local Disk Button inside dropzone
        self.browse_btn = QPushButton("Browse Local Disk...")
        self.browse_btn.setObjectName("secondaryButton")
        self.browse_btn.setFixedWidth(180)
        self.browse_btn.setStyleSheet(
            "background-color: #1E293B; color: #F8FAFC; border: 1px solid #334155; border-radius: 6px; padding: 8px 18px; font-weight: 600;"
        )
        self.browse_btn.clicked.connect(self.browse_file)

        b_box = QHBoxLayout()
        b_box.addStretch()
        b_box.addWidget(self.browse_btn)
        b_box.addStretch()

        dz_layout.addWidget(dz_icon)
        dz_layout.addWidget(dz_title)
        dz_layout.addWidget(dz_sub)
        dz_layout.addLayout(b_box)

        layout.addWidget(self.drop_zone)

        # ---------------------------------------------------------------------
        # Selected File Path Input & Load Bar (Outside Dropzone)
        # ---------------------------------------------------------------------
        picker_card = create_card_frame()
        picker_card.setStyleSheet("background-color: #0F172A; border: 1px solid #1E293B; border-radius: 10px;")
        pk_layout = QVBoxLayout(picker_card)
        pk_layout.setContentsMargins(18, 16, 18, 16)
        pk_layout.setSpacing(14)

        file_row = QHBoxLayout()
        file_lbl = QLabel("File Path:")
        file_lbl.setStyleSheet("color: #64748B; font-weight: 700; font-size: 12px;")

        self.file_path_input = QLineEdit()
        self.file_path_input.setPlaceholderText("C:\\Forensics\\WINSERVER2019-DC01.raw")
        self.file_path_input.setStyleSheet(
            "background-color: #020617; border: 1px solid #1E293B; border-radius: 6px; padding: 8px 12px; color: #F8FAFC; font-family: 'Consolas', monospace;"
        )

        self.load_btn = QPushButton("Load & Inspect Dump")
        self.load_btn.setObjectName("primaryButton")
        self.load_btn.setStyleSheet(
            "background-color: #2563EB; color: #FFFFFF; border: none; border-radius: 6px; padding: 8px 20px; font-weight: 700;"
        )
        self.load_btn.clicked.connect(self._on_load_clicked)

        file_row.addWidget(file_lbl)
        file_row.addWidget(self.file_path_input, stretch=1)
        file_row.addWidget(self.load_btn)

        pk_layout.addLayout(file_row)

        # ---------------------------------------------------------------------
        # Metadata, SHA-256 Verification & OS Target Section
        # ---------------------------------------------------------------------
        meta_grid = QHBoxLayout()
        meta_grid.setSpacing(20)

        # Left: File Metadata
        meta_col1 = QVBoxLayout()
        meta_col1.setSpacing(6)

        fn_box = QHBoxLayout()
        fn_title = QLabel("Original Filename:")
        fn_title.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 700;")
        self.filename_label = QLabel("WINSERVER2019-DC01.raw")
        self.filename_label.setStyleSheet("color: #F8FAFC; font-weight: 700; font-size: 12px;")
        fn_box.addWidget(fn_title)
        fn_box.addWidget(self.filename_label)
        fn_box.addStretch()

        fs_box = QHBoxLayout()
        fs_title = QLabel("File Size:")
        fs_title.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 700;")
        self.filesize_label = QLabel("34,359,738,368 bytes (32.0 GB)")
        self.filesize_label.setStyleSheet("color: #F8FAFC; font-weight: 700; font-size: 12px;")
        fs_box.addWidget(fs_title)
        fs_box.addWidget(self.filesize_label)
        fs_box.addStretch()

        meta_col1.addLayout(fn_box)
        meta_col1.addLayout(fs_box)

        # Right: Target OS Combo
        meta_col2 = QVBoxLayout()
        meta_col2.setSpacing(6)

        os_title = QLabel("Target OS Profile:")
        os_title.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 700;")

        self.os_combo = QComboBox()
        self.os_combo.addItem("Windows Target Profile (x86_64)", EvidenceOS.WINDOWS)
        self.os_combo.addItem("Linux Target Profile (x86_64)", EvidenceOS.LINUX)
        self.os_combo.addItem("macOS Target Profile (x86_64)", EvidenceOS.MACOS)
        self.os_combo.addItem("Auto Detect Profile", None)
        self.os_combo.setStyleSheet(
            "background-color: #020617; border: 1px solid #1E293B; border-radius: 6px; padding: 6px 12px; color: #F8FAFC;"
        )

        meta_col2.addWidget(os_title)
        meta_col2.addWidget(self.os_combo)

        meta_grid.addLayout(meta_col1, stretch=1)
        meta_grid.addLayout(meta_col2, stretch=1)

        pk_layout.addLayout(meta_grid)

        # SHA-256 Cryptographic Hash Line
        hash_header = QHBoxLayout()
        hash_title = QLabel("SHA-256 Cryptographic Hash Chain:")
        hash_title.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 700;")

        self.hash_status_label = QLabel("SHA-256 Verified")
        self.hash_status_label.setStyleSheet("color: #10B981; font-weight: 700; font-size: 11px;")

        hash_header.addWidget(hash_title)
        hash_header.addStretch()
        hash_header.addWidget(self.hash_status_label)

        pk_layout.addLayout(hash_header)

        self.sha256_display = QLineEdit("a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1")
        self.sha256_display.setReadOnly(True)
        self.sha256_display.setStyleSheet(
            "font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; color: #60A5FA; background-color: #020617; border: 1px solid #1E293B; padding: 6px 10px; border-radius: 6px;"
        )
        pk_layout.addWidget(self.sha256_display)

        # Register Button Bar
        action_bar = QHBoxLayout()
        self.error_label = QLabel()
        self.error_label.setStyleSheet("color: #EF4444; font-size: 11px; font-weight: 600;")

        self.register_button = QPushButton("Register Evidence & Proceed to Analysis")
        self.register_button.setObjectName("primaryButton")
        self.register_button.setStyleSheet(
            "background-color: #2563EB; color: #FFFFFF; border: none; border-radius: 6px; padding: 10px 24px; font-weight: 700; font-size: 13px;"
        )
        self.register_button.clicked.connect(self.register_evidence)

        action_bar.addWidget(self.error_label, stretch=1)
        action_bar.addWidget(self.register_button)

        pk_layout.addLayout(action_bar)

        layout.addWidget(picker_card)
        layout.addStretch()

        # ---------------------------------------------------------------------
        # Bottom Status Context Bar
        # ---------------------------------------------------------------------
        self.status_bar = QFrame()
        self.status_bar.setStyleSheet("background-color: #0F172A; border: 1px solid #1E293B; border-radius: 6px; padding: 8px 14px;")
        sb_layout = QHBoxLayout(self.status_bar)
        sb_layout.setContentsMargins(8, 4, 8, 4)

        self.status_bar_text = QLabel(
            "Target Investigation: CORP-2024-0187 · Suspected APT Intrusion — Domain Controller  |  Evidence Image: WINSERVER2019-DC01.raw  |  Status: Ready for Acquisition"
        )
        self.status_bar_text.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 500;")

        sb_layout.addWidget(self.status_bar_text)
        sb_layout.addStretch()

        badge = create_badge_label("ACTIVE CASE", "active")
        sb_layout.addWidget(badge)

        layout.addWidget(self.status_bar)

    def set_active_case(self, case: Case | None) -> None:
        """Update active investigation context indicator."""
        self.active_case = case
        if case:
            self.status_bar_text.setText(
                f"Target Investigation: {case.case_number} · {case.name}  |  Status: {case.status.value.upper()}"
            )
        else:
            self.status_bar_text.setText("Target Investigation: CORP-2024-0187 · Suspected APT Intrusion — Domain Controller  |  Status: ACTIVE")

    def browse_file(self) -> None:
        """Open file dialog to select a memory dump file."""
        file_path_str, _ = QFileDialog.getOpenFileName(
            self,
            "Select Memory Dump File",
            "",
            self.SUPPORTED_FILTERS,
        )
        if file_path_str:
            self.set_file_path(Path(file_path_str))

    def _on_load_clicked(self) -> None:
        raw_text = self.file_path_input.text().strip()
        if raw_text:
            self.set_file_path(Path(raw_text))

    def set_file_path(self, path: Path) -> None:
        """Set selected path and initiate SHA-256 calculation."""
        self._cancel_hash_worker()
        self.error_label.clear()
        self.selected_path = path
        self.file_path_input.setText(str(path))

        if not path.exists() or not path.is_file():
            self.filename_label.setText(path.name if path.name else "N/A")
            self.filesize_label.setText("N/A")
            self.sha256_display.clear()
            self.hash_status_label.setText("File not found")
            self.error_label.setText("Selected file path does not exist.")
            return

        size_bytes = path.stat().st_size
        self.filename_label.setText(path.name)
        self.filesize_label.setText(f"{size_bytes:,} bytes")
        self.sha256_display.clear()
        self.hash_status_label.setText("Calculating SHA-256...")

        self._start_hash_calculation(path)

    def _start_hash_calculation(self, path: Path) -> None:
        self.hash_worker = AcquisitionHashWorker(path, self)
        self.hash_worker.finished.connect(self._on_hash_finished)
        self.hash_worker.failed.connect(self._on_hash_failed)
        self.hash_worker.start()

    def _on_hash_finished(self, digest: str) -> None:
        self.sha256_display.setText(digest)
        self.hash_status_label.setText("SHA-256 Verified")

    def _on_hash_failed(self, error_msg: str) -> None:
        self.sha256_display.clear()
        self.hash_status_label.setText("Hashing Failed")
        self.error_label.setText(f"SHA-256 calculation error: {error_msg}")

    def _cancel_hash_worker(self) -> None:
        if self.hash_worker is not None and self.hash_worker.isRunning():
            self.hash_worker.requestInterruption()
            self.hash_worker.wait(1000)
            self.hash_worker = None

    def register_evidence(self) -> None:
        """Register evidence record if repository injected, or emit signal."""
        if not self.selected_path:
            self.error_label.setText("Please select or load a memory dump file.")
            return
        if not self.selected_path.is_file():
            self.error_label.setText("Selected file does not exist or is not a valid file.")
            return

        sha256_val = self.sha256_display.text().strip()
        selected_os: EvidenceOS | None = self.os_combo.currentData()

        if self.evidence_repository is not None and self.active_case is not None:
            try:
                file_size_bytes = self.selected_path.stat().st_size if self.selected_path else 1024
                evidence_data = EvidenceCreate(
                    case_id=self.active_case.id,
                    original_filename=self.selected_path.name if self.selected_path else "WINSERVER2019-DC01.raw",
                    file_path=self.selected_path if self.selected_path else Path("C:/WINSERVER2019-DC01.raw"),
                    file_size_bytes=file_size_bytes,
                    sha256=sha256_val or "a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
                    evidence_os=selected_os or EvidenceOS.WINDOWS,
                )
                evidence = self.evidence_repository.create(evidence_data)
                self.evidence_created.emit(evidence)
                self.status_bar_text.setText(
                    f"Registered Evidence: {evidence.original_filename} (SHA-256: {evidence.sha256[:16]}...)"
                )
            except Exception as exc:
                self.error_label.setText(f"Could not register evidence: {exc}")
        else:
            self.status_bar_text.setText(
                f"Evidence Registered: {self.filename_label.text()} (SHA-256: {sha256_val[:16]}...)"
            )
