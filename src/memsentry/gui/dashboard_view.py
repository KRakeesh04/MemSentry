"""Command Center / Triage Dashboard view for MemSentry, matching Figma visual reference."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from memsentry.app.artifact_service import ArtifactService, ProcessItemViewModel
from memsentry.gui.theme import (
    COLOR_BG_DARK,
    create_badge_label,
    create_card_frame,
)
from memsentry.models.case import Case


class DashboardView(QWidget):
    """Command Center Dashboard matching the Figma investigation suite reference."""

    open_investigation_requested = Signal()
    import_dump_requested = Signal()
    view_all_findings_requested = Signal()

    def __init__(
        self,
        artifact_service: ArtifactService | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.artifact_service = artifact_service
        self.active_case: Case | None = None
        self.setStyleSheet(f"background-color: {COLOR_BG_DARK};")
        self._build_ui()

    def _build_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(24, 20, 24, 20)
        layout.setSpacing(20)

        # ---------------------------------------------------------------------
        # Top Header Section: Case Subtitle, Large Title, Meta info & Tags
        # ---------------------------------------------------------------------
        header_container = QHBoxLayout()

        header_left = QVBoxLayout()
        header_left.setSpacing(6)

        sub_label = QLabel("FORENSIC COMMAND CENTER")
        sub_label.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 800; letter-spacing: 1px;")

        self.title_label = QLabel("Suspected APT Intrusion — Domain Controller")
        self.title_label.setStyleSheet("color: #F8FAFC; font-size: 24px; font-weight: 800;")

        # Metadata line + tag pills
        meta_layout = QHBoxLayout()
        meta_layout.setSpacing(12)

        self.meta_label = QLabel("CORP-2024-0187  ·  Analyst: J. Mercer  ·  Opened: Nov 15, 2024 - 06:00")
        self.meta_label.setStyleSheet("color: #94A3B8; font-size: 12px; font-weight: 500;")

        meta_layout.addWidget(self.meta_label)

        # Tags
        tags = ["APT", "Living-off-the-land", "C2", "Process Injection"]
        for tag in tags:
            t_lbl = QLabel(tag)
            t_lbl.setStyleSheet(
                "background-color: #1E293B; color: #94A3B8; border: 1px solid #334155; border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 600;"
            )
            meta_layout.addWidget(t_lbl)

        meta_layout.addStretch()

        header_left.addWidget(sub_label)
        header_left.addWidget(self.title_label)
        header_left.addLayout(meta_layout)

        # Top Right Action Buttons
        header_right = QHBoxLayout()
        header_right.setSpacing(10)

        import_btn = QPushButton("⬇  Import Dump")
        import_btn.setObjectName("secondaryButton")
        import_btn.setStyleSheet(
            "background-color: #1E293B; color: #F3F4F6; border: 1px solid #334155; border-radius: 6px; padding: 8px 16px; font-weight: 600;"
        )
        import_btn.clicked.connect(self.import_dump_requested.emit)

        open_inv_btn = QPushButton("🔍  Open Investigation")
        open_inv_btn.setObjectName("primaryButton")
        open_inv_btn.setStyleSheet(
            "background-color: #2563EB; color: #FFFFFF; border: none; border-radius: 6px; padding: 8px 18px; font-weight: 700;"
        )
        open_inv_btn.clicked.connect(self.open_investigation_requested.emit)

        header_right.addWidget(import_btn)
        header_right.addWidget(open_inv_btn)

        header_container.addLayout(header_left, stretch=1)
        header_container.addLayout(header_right)

        layout.addLayout(header_container)

        # ---------------------------------------------------------------------
        # Main Grid Splitter (Left: Primary Evidence & Findings, Right: Recent Cases)
        # ---------------------------------------------------------------------
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background-color: transparent; }")

        # Left Column Container
        left_widget = QWidget()
        left_widget.setStyleSheet(f"background-color: {COLOR_BG_DARK};")
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 12, 0)
        left_layout.setSpacing(20)

        # 1. Primary Evidence Card
        ev_card = create_card_frame()
        ev_card.setStyleSheet("background-color: #0F172A; border: 1px solid #1E293B; border-radius: 10px;")
        ev_layout = QVBoxLayout(ev_card)
        ev_layout.setContentsMargins(20, 20, 20, 20)
        ev_layout.setSpacing(16)

        # Card Header
        ev_header = QHBoxLayout()
        ev_sub = QLabel("PRIMARY EVIDENCE  ·  EVD-001")
        ev_sub.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 800; letter-spacing: 0.5px;")

        self.hash_badge = create_badge_label("✓  SHA-256 Verified", "success")
        self.hash_badge.setStyleSheet(
            "background-color: rgba(16, 185, 129, 0.15); color: #10B981; border: 1px solid #10B981; border-radius: 4px; padding: 4px 10px; font-weight: 700; font-size: 11px;"
        )

        ev_header.addWidget(ev_sub)
        ev_header.addStretch()
        ev_header.addWidget(self.hash_badge)

        self.ev_title = QLabel("WINSERVER2019-DC01.raw")
        self.ev_title.setStyleSheet("color: #F8FAFC; font-size: 20px; font-weight: 800;")

        # Key-Value Telemetry Grid (OS, Arch, Memory, Profile)
        grid_layout = QHBoxLayout()
        grid_layout.setSpacing(24)

        grid_layout.addLayout(self._create_meta_col("OPERATING SYSTEM", "Windows Server 2019"))
        grid_layout.addLayout(self._create_meta_col("ARCHITECTURE", "x86_64"))
        grid_layout.addLayout(self._create_meta_col("MEMORY SIZE", "32.0 GB"))
        grid_layout.addLayout(self._create_meta_col("KERNEL PROFILE", "Win10x64_19041"))
        grid_layout.addStretch()

        # SHA-256 Hash Box
        hash_box = QVBoxLayout()
        hash_box.setSpacing(4)
        hash_lbl = QLabel("SHA-256")
        hash_lbl.setStyleSheet("color: #64748B; font-size: 10px; font-weight: 700;")

        self.hash_val_label = QLabel("a3f8b2c1d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1")
        self.hash_val_label.setStyleSheet(
            "font-family: 'Consolas', 'Courier New', monospace; font-size: 12px; color: #94A3B8; background-color: #020617; border: 1px solid #1E293B; padding: 8px 12px; border-radius: 6px;"
        )

        hash_box.addWidget(hash_lbl)
        hash_box.addWidget(self.hash_val_label)

        ev_layout.addLayout(ev_header)
        ev_layout.addWidget(self.ev_title)
        ev_layout.addLayout(grid_layout)
        ev_layout.addLayout(hash_box)

        left_layout.addWidget(ev_card)

        # 2. Active Findings Section
        findings_header = QHBoxLayout()
        af_title = QLabel("Active Findings")
        af_title.setStyleSheet("color: #F8FAFC; font-size: 16px; font-weight: 800;")

        view_all_btn = QPushButton("View all →")
        view_all_btn.setFlat(True)
        view_all_btn.setStyleSheet("color: #3B82F6; font-size: 13px; font-weight: 600; text-align: right;")
        view_all_btn.clicked.connect(self.view_all_findings_requested.emit)

        findings_header.addWidget(af_title)
        findings_header.addStretch()
        findings_header.addWidget(view_all_btn)

        left_layout.addLayout(findings_header)

        # Findings Rows List
        findings_container = QVBoxLayout()
        findings_container.setSpacing(10)

        findings_data = [
            ("CRITICAL", "Malicious Office Macro — PowerShell Execution", "windows.pstree  ·  Confidence 94%  ·  Confirmed", "FND-001"),
            ("CRITICAL", "C2 Beacon — TOR Exit Node (Cobalt Strike)", "windows.netstat  ·  Confidence 91%  ·  Confirmed", "FND-002"),
            ("CRITICAL", "Process Injection — Hollow Process Injection", "windows.malfind  ·  Confidence 87%  ·  Confirmed", "FND-003"),
            ("HIGH", "Reverse Shell — Meterpreter on Port 4444", "windows.netscan  ·  Confidence 82%  ·  Reviewing", "FND-004"),
        ]

        for sev, f_title, f_sub, f_id in findings_data:
            f_card = create_card_frame()
            f_card.setStyleSheet("background-color: #0F172A; border: 1px solid #1E293B; border-radius: 8px;")
            f_row = QHBoxLayout(f_card)
            f_row.setContentsMargins(16, 12, 16, 12)
            f_row.setSpacing(14)

            badge = create_badge_label(sev, sev.lower())
            badge.setFixedWidth(80)

            f_info = QVBoxLayout()
            f_info.setSpacing(2)
            t_lbl = QLabel(f_title)
            t_lbl.setStyleSheet("color: #F1F5F9; font-size: 13px; font-weight: 700;")
            s_lbl = QLabel(f_sub)
            s_lbl.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 500;")
            f_info.addWidget(t_lbl)
            f_info.addWidget(s_lbl)

            id_lbl = QLabel(f_id)
            id_lbl.setStyleSheet("color: #475569; font-size: 11px; font-weight: 700;")

            f_row.addWidget(badge)
            f_row.addLayout(f_info, stretch=1)
            f_row.addWidget(id_lbl)

            findings_container.addWidget(f_card)

        left_layout.addLayout(findings_container)
        left_layout.addStretch()

        splitter.addWidget(left_widget)

        # ---------------------------------------------------------------------
        # Right Column Container (Recent Cases & Quick Actions Sidebar)
        # ---------------------------------------------------------------------
        right_widget = QWidget()
        right_widget.setStyleSheet(f"background-color: {COLOR_BG_DARK};")
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(12, 0, 0, 0)
        right_layout.setSpacing(16)

        # Tab Header Row
        tabs_box = QHBoxLayout()
        tabs_box.setSpacing(16)

        recent_tab = QPushButton("Recent Cases")
        recent_tab.setStyleSheet(
            "background-color: #1E3A8A; color: #FFFFFF; border: none; border-radius: 6px; padding: 6px 14px; font-weight: 700;"
        )

        quick_tab = QPushButton("Quick Actions")
        quick_tab.setStyleSheet(
            "background-color: transparent; color: #64748B; border: none; font-weight: 600;"
        )

        tabs_box.addWidget(recent_tab)
        tabs_box.addWidget(quick_tab)
        tabs_box.addStretch()

        right_layout.addLayout(tabs_box)

        # Cases Scroll List (Clean dark styling, no white backgrounds)
        cases_scroll = QScrollArea()
        cases_scroll.setWidgetResizable(True)
        cases_scroll.setStyleSheet(
            "QScrollArea { border: none; background-color: #0B0F19; }"
            "QScrollBar:vertical { background-color: #0B0F19; width: 6px; }"
            "QScrollBar::handle:vertical { background-color: #1E293B; border-radius: 3px; }"
        )

        cases_content = QWidget()
        cases_content.setObjectName("casesContent")
        cases_content.setStyleSheet("background-color: #0B0F19;")
        cases_box = QVBoxLayout(cases_content)
        cases_box.setContentsMargins(0, 0, 0, 0)
        cases_box.setSpacing(12)

        mock_cases = [
            (
                "Suspected APT Intrusion — Domain Controller",
                "CRITICAL",
                "CORP-2024-0187  ·  Windows  ·  2 min ago",
                "ACTIVE",
                "5 findings",
                "J. Mercer",
                True,
            ),
            (
                "Ransomware Staging — FILESERVER-02",
                "HIGH",
                "CORP-2024-0182  ·  Windows  ·  3h ago",
                "ACTIVE",
                "8 findings",
                "A. Torres",
                False,
            ),
            (
                "Credential Dumping — Workstation Fleet",
                "HIGH",
                "CORP-2024-0175  ·  Windows  ·  1d ago",
                "REVIEW",
                "3 findings",
                "J. Mercer",
                False,
            ),
            (
                "Rootkit Detection — Ubuntu 22.04 Server",
                "MEDIUM",
                "CORP-2024-0162  ·  Linux  ·  5d ago",
                "CLOSED",
                "2 findings",
                "K. Osei",
                False,
            ),
        ]

        for c_title, sev, meta, status, f_cnt, analyst, is_active in mock_cases:
            c_card = create_card_frame()
            card_bg = "#1E293B" if is_active else "#0F172A"
            border_color = "#3B82F6" if is_active else "#1E293B"
            c_card.setStyleSheet(f"background-color: {card_bg}; border: 1px solid {border_color}; border-radius: 8px;")

            c_layout = QVBoxLayout(c_card)
            c_layout.setContentsMargins(14, 12, 14, 12)
            c_layout.setSpacing(8)

            c_head = QHBoxLayout()
            ct_lbl = QLabel(c_title)
            ct_lbl.setStyleSheet("color: #F8FAFC; font-size: 13px; font-weight: 700;")
            ct_lbl.setWordWrap(True)

            sev_pill = create_badge_label(sev, sev.lower())

            c_head.addWidget(ct_lbl, stretch=1)
            c_head.addWidget(sev_pill)

            c_meta = QLabel(meta)
            c_meta.setStyleSheet("color: #64748B; font-size: 11px; font-weight: 500;")

            c_foot = QHBoxLayout()
            st_pill = create_badge_label(status, "active" if status == "ACTIVE" else "info")
            fn_lbl = QLabel(f"{f_cnt}  ·  {analyst}")
            fn_lbl.setStyleSheet("color: #94A3B8; font-size: 11px; font-weight: 500;")

            c_foot.addWidget(st_pill)
            c_foot.addStretch()
            c_foot.addWidget(fn_lbl)

            c_layout.addLayout(c_head)
            c_layout.addWidget(c_meta)
            c_layout.addLayout(c_foot)

            cases_box.addWidget(c_card)

        cases_box.addStretch()
        cases_scroll.setWidget(cases_content)

        right_layout.addWidget(cases_scroll)

        splitter.addWidget(right_widget)
        splitter.setSizes([700, 320])

        layout.addWidget(splitter)

    def _create_meta_col(self, title: str, value: str) -> QVBoxLayout:
        col = QVBoxLayout()
        col.setSpacing(4)

        t_lbl = QLabel(title)
        t_lbl.setStyleSheet("color: #64748B; font-size: 10px; font-weight: 700; letter-spacing: 0.5px;")

        v_lbl = QLabel(value)
        v_lbl.setStyleSheet("color: #F8FAFC; font-size: 14px; font-weight: 700;")

        col.addWidget(t_lbl)
        col.addWidget(v_lbl)
        return col

    def set_active_case(self, case: Case | None) -> None:
        """Update dashboard telemetry when active investigation changes."""
        self.active_case = case
        if case:
            self.title_label.setText(f"{case.name}")
            self.meta_label.setText(f"{case.case_number}  ·  Analyst: J. Mercer  ·  Status: {case.status.value.upper()}")

    def load_persisted_telemetry_for_evidence(self, evidence_id: object) -> None:
        """Fetch persisted artifact view models and update dashboard metrics."""
        if self.artifact_service is None:
            return

        run_id = self.artifact_service.get_latest_analysis_run_for_evidence(evidence_id)  # type: ignore[arg-type]
        if run_id is None:
            return

        vms = self.artifact_service.get_processes_for_analysis_run(run_id)
        if not vms:
            return

        self.update_persisted_metrics(vms)

    def update_persisted_metrics(self, vms: list[ProcessItemViewModel]) -> None:
        """Update dashboard counts based on persisted process models."""
        total_procs = len(vms)
        suspicious_cnt = sum(1 for v in vms if v.is_suspicious)
        sockets_cnt = sum(len(v.sockets) for v in vms)

        # Update meta subtitle with real counts if active
        if self.active_case:
            self.meta_label.setText(
                f"{self.active_case.case_number}  ·  Processes: {total_procs}  ·  "
                f"Sockets: {sockets_cnt}  ·  Suspicious: {suspicious_cnt}"
            )
