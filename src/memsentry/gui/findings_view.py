"""Process-level Triage Findings Dashboard view for MemSentry.

Presents correlated threat indicators, severity rankings, MITRE ATT&CK mappings,
linked evidence artifacts, and evidence chain provenance.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QProgressBar,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from memsentry.gui.theme import create_badge_label
from memsentry.models.case import Case

SAMPLE_FINDINGS: list[dict[str, Any]] = [
    {
        "id": "FND-001",
        "title": "Malicious Office Macro — PowerShell Execution",
        "severity": "CRITICAL",
        "status": "CONFIRMED",
        "status_label": "Investigator Confirmed",
        "mitre_id": "T1566.001",
        "mitre_title": "T1566.001  Phishing: Spearphishing Attachment",
        "plugin": "windows.pstree",
        "timestamp": "2024-11-15 07:52:13",
        "confidence": 94,
        "description": (
            "WINWORD.EXE (PID 8192) opened Q4_Budget_Review.docm and subsequently spawned a "
            "PowerShell instance (PID 9248) with a base64-encoded command line. Office applications "
            "spawning PowerShell with encoded arguments is a hallmark of malicious macro execution "
            "used for initial access via spear-phishing."
        ),
        "linked_artifacts": [
            ("PID:8192 →", "explorer"),
            ("PID:9248 →", "explorer"),
            ("FILE:Q4_Budget_Review.docm →", "files"),
        ],
        "evidence_chain": [
            "WINSERVER2019-DC01.raw",
            "WINWORD.EXE (PID 8192)",
            "powershell.exe (PID 9248)",
            "EVD-001",
        ],
    },
    {
        "id": "FND-002",
        "title": "C2 Beacon — TOR Exit Node (Cobalt Strike)",
        "severity": "CRITICAL",
        "status": "CONFIRMED",
        "status_label": "Investigator Confirmed",
        "mitre_id": "T1071.001",
        "mitre_title": "T1071.001  Application Layer Protocol: Web Protocols",
        "plugin": "windows.netstat",
        "timestamp": "2024-11-15 07:53:02",
        "confidence": 91,
        "description": (
            "powershell.exe (PID 9248) established an outbound HTTPS connection to 185.220.101.47:443, "
            "a known TOR exit node and Cobalt Strike C2 beacon endpoint. Continuous beaconing activity "
            "observed at 60-second jitter intervals."
        ),
        "linked_artifacts": [
            ("PID:9248 →", "explorer"),
            ("IP:185.220.101.47 →", "graph"),
        ],
        "evidence_chain": [
            "WINSERVER2019-DC01.raw",
            "powershell.exe (PID 9248)",
            "185.220.101.47:443",
            "EVD-002",
        ],
    },
    {
        "id": "FND-003",
        "title": "Process Injection — Hollowed svchost.exe",
        "severity": "CRITICAL",
        "status": "AUTO",
        "status_label": "Automated Rule Match",
        "mitre_id": "T1055.012",
        "mitre_title": "T1055.012  Process Injection: Process Hollowing",
        "plugin": "windows.malfind",
        "timestamp": "2024-11-15 07:54:19",
        "confidence": 89,
        "description": (
            "Volatility malfind detected an unbacked executable memory page (PAGE_EXECUTE_READWRITE) "
            "in svchost.exe (PID 10891). Shellcode header MZ detected at 0x7FF73B1A0000 spawned by rundll32.exe."
        ),
        "linked_artifacts": [
            ("PID:10891 →", "explorer"),
            ("ADDR:0x7FF73B1A0000 →", "memory"),
        ],
        "evidence_chain": [
            "WINSERVER2019-DC01.raw",
            "rundll32.exe (PID 10284)",
            "svchost.exe (PID 10891)",
            "EVD-003",
        ],
    },
    {
        "id": "FND-004",
        "title": "Reverse Shell — Meterpreter on Port 4444",
        "severity": "CRITICAL",
        "status": "CONFIRMED",
        "status_label": "Investigator Confirmed",
        "mitre_id": "T1059.003",
        "mitre_title": "T1059.003  Command and Scripting Interpreter: Windows Command Shell",
        "plugin": "windows.netstat",
        "timestamp": "2024-11-15 07:55:41",
        "confidence": 92,
        "description": (
            "svchost.exe (PID 10891) established an active reverse shell TCP connection to "
            "45.33.32.156:4444. Interactive command prompt traffic stream detected."
        ),
        "linked_artifacts": [
            ("PID:10891 →", "explorer"),
            ("IP:45.33.32.156:4444 →", "graph"),
        ],
        "evidence_chain": [
            "WINSERVER2019-DC01.raw",
            "svchost.exe (PID 10891)",
            "45.33.32.156:4444",
            "EVD-004",
        ],
    },
    {
        "id": "FND-005",
        "title": "Suspicious DLL — Temp Directory Loader (kb1281.dat)",
        "severity": "HIGH",
        "status": "AUTO",
        "status_label": "Automated Rule Match",
        "mitre_id": "T1574.002",
        "mitre_title": "T1574.002  Hijack Execution Flow: DLL Side-Loading",
        "plugin": "windows.dlllist",
        "timestamp": "2024-11-15 07:56:10",
        "confidence": 78,
        "description": (
            "rundll32.exe (PID 10284) loaded unsigned dynamic library C:\\Users\\...\\Temp\\kb1281.dat. "
            "File lacks valid digital signature and exports unusual ordinal routines."
        ),
        "linked_artifacts": [
            ("PID:10284 →", "explorer"),
            ("FILE:kb1281.dat →", "files"),
        ],
        "evidence_chain": [
            "WINSERVER2019-DC01.raw",
            "rundll32.exe (PID 10284)",
            "kb1281.dat",
            "EVD-005",
        ],
    },
]


class FindingCardWidget(QFrame):
    """Custom card representation for individual findings in the sidebar list."""

    clicked = Signal(str)

    def __init__(self, data: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.finding_id: str = data["id"]
        self.is_selected: bool = False
        self._init_ui(data)

    def _init_ui(self, data: dict[str, Any]) -> None:
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 10, 12, 10)
        layout.setSpacing(6)

        # Top Row: Badges & Finding ID
        top_box = QHBoxLayout()
        top_box.setSpacing(6)

        sev_badge = create_badge_label(data["severity"], "critical" if data["severity"] == "CRITICAL" else "high")
        top_box.addWidget(sev_badge)

        if data["status"] == "CONFIRMED":
            conf_badge = create_badge_label("✓ CONFIRMED", "info")
            conf_badge.setStyleSheet(
                "background: #064E3B; color: #34D399; font-size: 10px; font-weight: 700; border-radius: 3px; padding: 2px 6px;"
            )
            top_box.addWidget(conf_badge)
        else:
            auto_badge = create_badge_label("AUTO", "gray")
            auto_badge.setStyleSheet(
                "background: #1E293B; color: #94A3B8; font-size: 10px; font-weight: 700; border-radius: 3px; padding: 2px 6px;"
            )
            top_box.addWidget(auto_badge)

        top_box.addStretch()

        id_lbl = QLabel(data["id"])
        id_lbl.setStyleSheet("font-family: monospace; font-size: 11px; color: #64748B; font-weight: 600;")
        top_box.addWidget(id_lbl)

        layout.addLayout(top_box)

        # Title Row
        title_lbl = QLabel(data["title"])
        title_lbl.setWordWrap(True)
        title_lbl.setStyleSheet("font-size: 13px; font-weight: 700; color: #F8FAFC;")
        layout.addWidget(title_lbl)

        # Bottom Row: Plugin & Confidence Bar
        bottom_box = QHBoxLayout()
        bottom_box.setSpacing(8)

        plugin_lbl = QLabel(data["plugin"])
        plugin_lbl.setStyleSheet("font-family: monospace; font-size: 11px; color: #64748B;")
        bottom_box.addWidget(plugin_lbl)

        bottom_box.addStretch()

        # Confidence Bar
        conf_val = data["confidence"]
        bar = QProgressBar()
        bar.setRange(0, 100)
        bar.setValue(conf_val)
        bar.setTextVisible(False)
        bar.setFixedHeight(6)
        bar.setFixedWidth(80)
        bar_color = "#EF4444" if conf_val >= 90 else "#F59E0B"
        bar.setStyleSheet(
            f"QProgressBar {{ background: #1E293B; border: none; border-radius: 3px; }} "
            f"QProgressBar::chunk {{ background: {bar_color}; border-radius: 3px; }}"
        )
        bottom_box.addWidget(bar)

        pct_lbl = QLabel(f"{conf_val}%")
        pct_lbl.setStyleSheet(f"font-size: 11px; font-weight: 700; color: {bar_color};")
        bottom_box.addWidget(pct_lbl)

        layout.addLayout(bottom_box)

        self.update_style()

    def set_selected(self, selected: bool) -> None:
        self.is_selected = selected
        self.update_style()

    def update_style(self) -> None:
        if self.is_selected:
            self.setStyleSheet(
                "FindingCardWidget { background: #1E293B; border: 1px solid #3B82F6; "
                "border-left: 4px solid #EF4444; border-radius: 6px; }"
            )
        else:
            self.setStyleSheet(
                "FindingCardWidget { background: #0D1322; border: 1px solid #1E293B; "
                "border-left: 3px solid #334155; border-radius: 6px; } "
                "FindingCardWidget:hover { background: #151D30; border-color: #334155; }"
            )

    def mousePressEvent(self, event: object) -> None:
        self.clicked.emit(self.finding_id)


class FindingsView(QWidget):
    """View widget displaying correlated process-level findings, MITRE mappings, and risk scores."""

    open_relationship_graph_requested = Signal()
    open_evidence_explorer_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.active_case: Case | None = None
        self.cards_map: dict[str, FindingCardWidget] = {}
        self.selected_finding: dict[str, Any] = SAMPLE_FINDINGS[0]
        self._build_ui()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 12, 16, 12)
        main_layout.setSpacing(12)

        # 1. Top Sub-Header Bar
        header_box = QHBoxLayout()
        header_box.setSpacing(12)

        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)

        subtitle_lbl = QLabel("FINDINGS")
        subtitle_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B; letter-spacing: 0.5px;")
        title_layout.addWidget(subtitle_lbl)

        counts_box = QHBoxLayout()
        counts_box.setSpacing(12)

        c_total = QLabel("5 findings")
        c_total.setStyleSheet("font-size: 16px; font-weight: 800; color: #F8FAFC;")
        counts_box.addWidget(c_total)

        c_crit = QLabel("4 critical")
        c_crit.setStyleSheet("font-size: 14px; font-weight: 700; color: #EF4444;")
        counts_box.addWidget(c_crit)

        c_conf = QLabel("3 confirmed")
        c_conf.setStyleSheet("font-size: 14px; font-weight: 700; color: #10B981;")
        counts_box.addWidget(c_conf)

        title_layout.addLayout(counts_box)
        header_box.addLayout(title_layout)

        header_box.addStretch()

        # Filter Chips Bar
        chips_layout = QHBoxLayout()
        chips_layout.setSpacing(6)

        filters = [("All", True), ("Critical", False), ("High", False), ("Medium", False), ("Confirmed", False)]
        for name, active in filters:
            btn = QPushButton(name)
            if active:
                btn.setStyleSheet(
                    "background: #1E293B; border: 1px solid #3B82F6; color: #38BDF8; "
                    "font-size: 12px; font-weight: 600; padding: 4px 14px; border-radius: 4px;"
                )
            else:
                btn.setStyleSheet(
                    "background: #0F172A; border: 1px solid #1E293B; color: #94A3B8; "
                    "font-size: 12px; font-weight: 500; padding: 4px 14px; border-radius: 4px;"
                )
            chips_layout.addWidget(btn)

        header_box.addLayout(chips_layout)
        main_layout.addLayout(header_box)

        # 2. Main 2-Column Splitter (Left: Findings List, Right: Detail Panel)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background: #1E293B; width: 1px; }")

        # Left Column Container
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(8)

        scroll_list = QScrollArea()
        scroll_list.setWidgetResizable(True)
        scroll_list.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        list_container = QWidget()
        list_box = QVBoxLayout(list_container)
        list_box.setContentsMargins(0, 0, 6, 0)
        list_box.setSpacing(8)

        for data in SAMPLE_FINDINGS:
            card = FindingCardWidget(data)
            card.clicked.connect(self._on_card_clicked)
            self.cards_map[data["id"]] = card
            list_box.addWidget(card)

        list_box.addStretch()
        scroll_list.setWidget(list_container)
        left_layout.addWidget(scroll_list)

        splitter.addWidget(left_widget)

        # Right Column Detail Inspector Panel
        right_panel = QFrame()
        right_panel.setStyleSheet("background: #080C14; border: 1px solid #1E293B; border-radius: 6px;")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(20, 20, 20, 20)
        right_layout.setSpacing(14)

        # Detail Header & Action Row
        meta_top = QHBoxLayout()
        meta_top.setSpacing(8)

        self.detail_sev_badge = create_badge_label("CRITICAL", "critical")
        meta_top.addWidget(self.detail_sev_badge)

        self.detail_status_lbl = QLabel("✓ Investigator Confirmed")
        self.detail_status_lbl.setStyleSheet("color: #10B981; font-size: 12px; font-weight: 700;")
        meta_top.addWidget(self.detail_status_lbl)

        self.detail_mitre_badge = create_badge_label("T1566.001", "info")
        self.detail_mitre_badge.setStyleSheet(
            "background: #1E3A8A; color: #60A5FA; font-family: monospace; font-size: 11px; font-weight: 700; border-radius: 4px; padding: 2px 8px;"
        )
        meta_top.addWidget(self.detail_mitre_badge)

        meta_top.addStretch()

        report_btn = QPushButton("✓ In Report")
        report_btn.setStyleSheet(
            "background: #1D4ED8; border: 1px solid #2563EB; color: #F8FAFC; "
            "font-size: 12px; font-weight: 700; padding: 6px 16px; border-radius: 4px;"
        )
        meta_top.addWidget(report_btn)

        right_layout.addLayout(meta_top)

        # Finding Title & Subtitle Line
        self.detail_title_lbl = QLabel("Malicious Office Macro — PowerShell Execution")
        self.detail_title_lbl.setStyleSheet("font-size: 20px; font-weight: 800; color: #F8FAFC;")
        self.detail_title_lbl.setWordWrap(True)
        right_layout.addWidget(self.detail_title_lbl)

        self.detail_sub_lbl = QLabel("FND-001 · Plugin: windows.pstree · 2024-11-15 07:52:13")
        self.detail_sub_lbl.setStyleSheet("font-family: monospace; font-size: 12px; color: #64748B;")
        right_layout.addWidget(self.detail_sub_lbl)

        # Scrollable Content Area for Detail Panel
        detail_scroll = QScrollArea()
        detail_scroll.setWidgetResizable(True)
        detail_scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        detail_body = QWidget()
        detail_box = QVBoxLayout(detail_body)
        detail_box.setContentsMargins(0, 10, 8, 0)
        detail_box.setSpacing(14)

        # Confidence Section
        conf_hdr = QLabel("Confidence")
        conf_hdr.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B;")
        detail_box.addWidget(conf_hdr)

        conf_row = QHBoxLayout()
        conf_row.setSpacing(10)

        self.confidence_bar = QProgressBar()
        self.confidence_bar.setRange(0, 100)
        self.confidence_bar.setValue(94)
        self.confidence_bar.setTextVisible(False)
        self.confidence_bar.setFixedHeight(8)
        self.confidence_bar.setStyleSheet(
            "QProgressBar { background: #1E293B; border: none; border-radius: 4px; } "
            "QProgressBar::chunk { background: #EF4444; border-radius: 4px; }"
        )
        conf_row.addWidget(self.confidence_bar, stretch=1)

        self.confidence_pct_lbl = QLabel("94%")
        self.confidence_pct_lbl.setStyleSheet("font-size: 14px; font-weight: 800; color: #F8FAFC;")
        conf_row.addWidget(self.confidence_pct_lbl)

        detail_box.addLayout(conf_row)

        # Description & Evidence Section
        desc_hdr = QLabel("Description & Evidence")
        desc_hdr.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B;")
        detail_box.addWidget(desc_hdr)

        desc_card = QFrame()
        desc_card.setStyleSheet("background: #0F172A; border: 1px solid #1E293B; border-radius: 6px;")
        desc_box = QVBoxLayout(desc_card)
        desc_box.setContentsMargins(14, 14, 14, 14)

        self.desc_lbl = QLabel()
        self.desc_lbl.setWordWrap(True)
        self.desc_lbl.setStyleSheet("font-size: 13px; color: #CBD5E1; line-height: 1.5;")
        desc_box.addWidget(self.desc_lbl)
        detail_box.addWidget(desc_card)

        # MITRE ATT&CK Section
        mitre_hdr = QLabel("MITRE ATT&CK")
        mitre_hdr.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B;")
        detail_box.addWidget(mitre_hdr)

        mitre_card = QFrame()
        mitre_card.setStyleSheet("background: #0F172A; border: 1px solid #1E293B; border-radius: 6px;")
        mitre_box = QHBoxLayout(mitre_card)
        mitre_box.setContentsMargins(14, 12, 14, 12)

        self.mitre_full_lbl = QLabel()
        self.mitre_full_lbl.setStyleSheet("font-family: monospace; font-size: 13px; font-weight: 700; color: #60A5FA;")
        mitre_box.addWidget(self.mitre_full_lbl)
        mitre_box.addStretch()
        detail_box.addWidget(mitre_card)

        # Linked Artifacts Section
        artifacts_hdr = QLabel("Linked Artifacts")
        artifacts_hdr.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B;")
        detail_box.addWidget(artifacts_hdr)

        self.linked_artifacts_box = QHBoxLayout()
        self.linked_artifacts_box.setSpacing(8)
        self.linked_artifacts_box.addStretch()
        detail_box.addLayout(self.linked_artifacts_box)

        # Evidence Chain Section
        chain_hdr = QLabel("Evidence Chain")
        chain_hdr.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B;")
        detail_box.addWidget(chain_hdr)

        chain_card = QFrame()
        chain_card.setStyleSheet("background: #0F172A; border: 1px solid #1E293B; border-radius: 6px;")
        self.chain_box = QHBoxLayout(chain_card)
        self.chain_box.setContentsMargins(14, 10, 14, 10)
        self.chain_box.setSpacing(8)
        detail_box.addWidget(chain_card)

        # Floating Alert Banner
        alert_banner = QFrame()
        alert_banner.setStyleSheet("background: #0F172A; border: 1px solid #334155; border-radius: 6px;")
        alert_box = QHBoxLayout(alert_banner)
        alert_box.setContentsMargins(14, 8, 14, 8)

        warn_icon = QLabel("⚠️")
        warn_icon.setStyleSheet("font-size: 13px;")
        alert_box.addWidget(warn_icon)

        alert_msg = QLabel("Live preview failed ID: srid_8HA9Z7BYX247RY565JHN507R")
        alert_msg.setStyleSheet("color: #E2E8F0; font-size: 11px; font-weight: 600; font-family: monospace;")
        alert_box.addWidget(alert_msg)

        alert_box.addStretch()

        retry_btn = QPushButton("Retry")
        retry_btn.setStyleSheet(
            "background: #1E293B; border: 1px solid #475569; color: #F8FAFC; "
            "font-size: 11px; font-weight: 600; padding: 3px 12px; border-radius: 4px;"
        )
        alert_box.addWidget(retry_btn)

        detail_box.addWidget(alert_banner)

        # Investigator Notes Section
        notes_hdr = QLabel("Investigator Notes")
        notes_hdr.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B;")
        detail_box.addWidget(notes_hdr)

        self.notes_edit = QTextEdit()
        self.notes_edit.setPlaceholderText("Add investigator observations or verification notes...")
        self.notes_edit.setFixedHeight(70)
        self.notes_edit.setStyleSheet(
            "background: #0F172A; border: 1px solid #1E293B; color: #E2E8F0; "
            "font-size: 12px; border-radius: 6px; padding: 8px;"
        )
        detail_box.addWidget(self.notes_edit)

        detail_scroll.setWidget(detail_body)
        right_layout.addWidget(detail_scroll)

        splitter.addWidget(right_panel)
        splitter.setSizes([380, 620])

        main_layout.addWidget(splitter, stretch=1)

        # Select first card initially
        self._on_card_clicked("FND-001")

    def _on_card_clicked(self, finding_id: str) -> None:
        for fid, card in self.cards_map.items():
            card.set_selected(fid == finding_id)

        finding = next((f for f in SAMPLE_FINDINGS if f["id"] == finding_id), None)
        if not finding:
            return

        self.selected_finding = finding

        # Update Detail Meta Header
        self.detail_sev_badge.setText(finding["severity"])
        if finding["status"] == "CONFIRMED":
            self.detail_status_lbl.setText("✓ Investigator Confirmed")
            self.detail_status_lbl.setStyleSheet("color: #10B981; font-size: 12px; font-weight: 700;")
        else:
            self.detail_status_lbl.setText("Automated Rule Match")
            self.detail_status_lbl.setStyleSheet("color: #94A3B8; font-size: 12px; font-weight: 700;")

        self.detail_mitre_badge.setText(finding["mitre_id"])
        self.detail_title_lbl.setText(finding["title"])
        self.detail_sub_lbl.setText(
            f"{finding['id']} · Plugin: {finding['plugin']} · {finding['timestamp']}"
        )

        # Confidence Bar
        conf_val = finding["confidence"]
        self.confidence_bar.setValue(conf_val)
        self.confidence_pct_lbl.setText(f"{conf_val}%")

        # Description
        self.desc_lbl.setText(finding["description"])

        # MITRE Full Title
        self.mitre_full_lbl.setText(finding["mitre_title"])

        # Linked Artifacts Chips
        while self.linked_artifacts_box.count():
            child = self.linked_artifacts_box.takeAt(0)
            if child:
                w = child.widget()
                if w is not None:
                    w.deleteLater()

        for art_text, nav_target in finding["linked_artifacts"]:
            btn = QPushButton(art_text)
            btn.setStyleSheet(
                "background: #1E293B; border: 1px solid #334155; color: #38BDF8; "
                "font-family: monospace; font-size: 11px; font-weight: 600; padding: 4px 10px; border-radius: 4px;"
            )
            btn.setCursor(Qt.CursorShape.PointingHandCursor)
            if nav_target == "graph":
                btn.clicked.connect(self.open_relationship_graph_requested.emit)
            else:
                btn.clicked.connect(self.open_evidence_explorer_requested.emit)
            self.linked_artifacts_box.addWidget(btn)
        self.linked_artifacts_box.addStretch()

        # Evidence Chain Flow
        while self.chain_box.count():
            child = self.chain_box.takeAt(0)
            if child:
                w = child.widget()
                if w is not None:
                    w.deleteLater()

        chain_items = finding["evidence_chain"]
        for idx, item_text in enumerate(chain_items):
            chip = QLabel(item_text)
            chip.setStyleSheet(
                "background: #1E293B; color: #E2E8F0; font-family: monospace; "
                "font-size: 11px; font-weight: 600; padding: 4px 8px; border-radius: 4px;"
            )
            self.chain_box.addWidget(chip)

            if idx < len(chain_items) - 1:
                arr = QLabel("→")
                arr.setStyleSheet("color: #64748B; font-size: 12px; font-weight: 700;")
                self.chain_box.addWidget(arr)
        self.chain_box.addStretch()

    def set_active_case(self, case: Case | None) -> None:
        """Propagate active case to view."""
        self.active_case = case
