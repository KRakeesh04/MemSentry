"""Investigation Timeline view for MemSentry.

Presents chronological forensic events across process execution, network sockets,
file modifications, and memory acquisition with timeline node track and event inspector.
"""

from __future__ import annotations

from typing import Any

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSplitter,
    QVBoxLayout,
    QWidget,
)

from memsentry.gui.theme import create_badge_label
from memsentry.models.case import Case

SAMPLE_TIMELINE_EVENTS: list[dict[str, Any]] = [
    {
        "id": "EVT-001",
        "timestamp_short": "07:45:00",
        "timestamp_full": "2024-11-15 07:45:00",
        "type": "acquisition",
        "category_label": "Acquisition",
        "severity": "info",
        "title": "Memory acquisition started on WINSERVER2019-DC01",
        "subtext_1": "EVD-001",
        "subtext_2": "Memory Dump File: WINSERVER2019-DC01.raw",
        "artifact": "EVD-001",
        "icon": "↓",
        "icon_color": "#3B82F6",
        "details_box": "Raw RAM capture initialized via WinPmem Kernel Driver (32 GB total physical memory).",
    },
    {
        "id": "EVT-002",
        "timestamp_short": "07:45:18",
        "timestamp_full": "2024-11-15 07:45:18",
        "type": "acquisition",
        "category_label": "Acquisition",
        "severity": "info",
        "title": "Memory acquisition completed — 32.0 GB, SHA-256 verified",
        "subtext_1": "EVD-001",
        "subtext_2": "SHA-256: a3f8b2c1d4e5f6a7...",
        "artifact": "EVD-001",
        "icon": "↓",
        "icon_color": "#3B82F6",
        "details_box": "SHA-256 hash calculated and registered. Evidence integrity status: VERIFIED.",
    },
    {
        "id": "EVT-003",
        "timestamp_short": "07:47:08",
        "timestamp_full": "2024-11-15 07:47:08",
        "type": "process",
        "category_label": "Process",
        "severity": "medium",
        "title": "WINWORD.EXE (PID 8192) opened Q4_Budget_Review.docm",
        "subtext_1": "User: CORP\\jdoe",
        "subtext_2": "PID:8192",
        "artifact": "PID:8192",
        "icon": "⬡",
        "icon_color": "#3B82F6",
        "details_box": "Microsoft Word 2019 executed under domain user account CORP\\jdoe opening macro-enabled document.",
    },
    {
        "id": "EVT-004",
        "timestamp_short": "07:47:31",
        "timestamp_full": "2024-11-15 07:47:31",
        "type": "process",
        "category_label": "Process",
        "severity": "critical",
        "title": "powershell.exe (PID 9248) spawned by WINWORD.EXE",
        "subtext_1": "Encoded command line (-enc)",
        "subtext_2": "PID:9248",
        "artifact": "PID:9248",
        "icon": "⬡",
        "icon_color": "#EF4444",
        "is_selected": True,
        "details_box": "Encoded command line (-enc)\npowershell -nop -w hidden -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAA...",
    },
    {
        "id": "EVT-005",
        "timestamp_short": "07:47:33",
        "timestamp_full": "2024-11-15 07:47:33",
        "type": "network",
        "category_label": "Network",
        "severity": "critical",
        "title": "powershell.exe connected to 185.220.101.47:443",
        "subtext_1": "TOR exit node — ESTABLISHED",
        "subtext_2": "185.220.101.47:443",
        "artifact": "185.220.101.47:443",
        "icon": "#",
        "icon_color": "#EF4444",
        "details_box": "TCP socket connection established to external IP 185.220.101.47 on port 443 (TOR Exit Node).",
    },
    {
        "id": "EVT-006",
        "timestamp_short": "07:49:10",
        "timestamp_full": "2024-11-15 07:49:10",
        "type": "process",
        "category_label": "Process",
        "severity": "high",
        "title": "cmd.exe (PID 9712) spawned by powershell.exe",
        "subtext_1": "Interactive command shell",
        "subtext_2": "PID:9712",
        "artifact": "PID:9712",
        "icon": "⬡",
        "icon_color": "#F59E0B",
        "details_box": "Child command interpreter process created by powershell.exe for local command execution.",
    },
    {
        "id": "EVT-007",
        "timestamp_short": "07:51:44",
        "timestamp_full": "2024-11-15 07:51:44",
        "type": "process",
        "category_label": "Process",
        "severity": "critical",
        "title": "svchost.exe (PID 10891) memory injected by rundll32.exe",
        "subtext_1": "Malfind PAGE_EXECUTE_READWRITE region detected",
        "subtext_2": "PID:10891",
        "artifact": "PID:10891",
        "icon": "⚡",
        "icon_color": "#EF4444",
        "details_box": "Unbacked executable memory allocation detected in svchost.exe memory space (Process Hollowing).",
    },
]


class TimelineCardWidget(QFrame):
    """Custom widget representing a single event card along the timeline track."""

    clicked = Signal(str)

    def __init__(self, data: dict[str, Any], parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.event_id: str = data["id"]
        self.is_selected: bool = data.get("is_selected", False)
        self._init_ui(data)

    def _init_ui(self, data: dict[str, Any]) -> None:
        self.setCursor(Qt.CursorShape.PointingHandCursor)

        main_box = QHBoxLayout(self)
        main_box.setContentsMargins(0, 0, 0, 0)
        main_box.setSpacing(12)

        # Left Timeline Track Node Icon
        node_box = QVBoxLayout()
        node_box.setContentsMargins(8, 6, 8, 6)
        node_box.setAlignment(Qt.AlignmentFlag.AlignTop | Qt.AlignmentFlag.AlignHCenter)

        node_circle = QLabel(data["icon"])
        circle_color = data["icon_color"]
        node_circle.setFixedSize(32, 32)
        node_circle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        if self.is_selected:
            node_circle.setStyleSheet(
                f"background: #1E293B; border: 2px solid #38BDF8; color: {circle_color}; "
                f"font-size: 14px; font-weight: 800; border-radius: 16px;"
            )
        else:
            node_circle.setStyleSheet(
                f"background: #0D1322; border: 1px solid #334155; color: {circle_color}; "
                f"font-size: 13px; font-weight: 700; border-radius: 16px;"
            )

        node_box.addWidget(node_circle)
        main_box.addLayout(node_box)

        # Right Event Card Box
        card_frame = QFrame()
        card_layout = QVBoxLayout(card_frame)
        card_layout.setContentsMargins(14, 12, 14, 12)
        card_layout.setSpacing(6)

        # Top Row: Category Pill, Severity Pill, Timestamp
        top_row = QHBoxLayout()
        top_row.setSpacing(6)

        cat_badge = create_badge_label(data["category_label"], "blue")
        top_row.addWidget(cat_badge)

        if data.get("severity") in ("critical", "high"):
            sev_text = data["severity"].upper()
            sev_badge = create_badge_label(sev_text, "critical" if data["severity"] == "critical" else "high")
            top_row.addWidget(sev_badge)

        top_row.addStretch()

        time_lbl = QLabel(data["timestamp_short"])
        time_lbl.setStyleSheet("font-family: monospace; font-size: 11px; color: #64748B; font-weight: 600;")
        top_row.addWidget(time_lbl)

        card_layout.addLayout(top_row)

        # Title Row
        title_lbl = QLabel(data["title"])
        title_lbl.setWordWrap(True)
        title_lbl.setStyleSheet("font-size: 13px; font-weight: 700; color: #F8FAFC;")
        card_layout.addWidget(title_lbl)

        # Subtext 1 Row
        if data.get("subtext_1"):
            sub1_lbl = QLabel(data["subtext_1"])
            sub1_lbl.setStyleSheet("font-size: 11px; color: #94A3B8;")
            card_layout.addWidget(sub1_lbl)

        # Subtext 2 Row
        if data.get("subtext_2"):
            sub2_lbl = QLabel(data["subtext_2"])
            sub2_lbl.setStyleSheet("font-family: monospace; font-size: 11px; color: #64748B;")
            card_layout.addWidget(sub2_lbl)

        self.card_frame = card_frame
        main_box.addWidget(card_frame, stretch=1)

        self.update_style()

    def set_selected(self, selected: bool) -> None:
        self.is_selected = selected
        self.update_style()

    def update_style(self) -> None:
        if self.is_selected:
            self.card_frame.setStyleSheet(
                "QFrame { background: #1E293B; border: 1px solid #3B82F6; "
                "border-left: 4px solid #38BDF8; border-radius: 6px; }"
            )
        else:
            self.card_frame.setStyleSheet(
                "QFrame { background: #0D1322; border: 1px solid #1E293B; "
                "border-radius: 6px; } "
                "QFrame:hover { background: #151D30; border-color: #334155; }"
            )

    def mousePressEvent(self, event: object) -> None:
        self.clicked.emit(self.event_id)


class TimelineView(QWidget):
    """Chronological investigation event timeline view matching Figma design."""

    open_relationship_graph_requested = Signal()
    open_evidence_explorer_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.active_case: Case | None = None
        self.cards_map: dict[str, TimelineCardWidget] = {}
        self.selected_event: dict[str, Any] = SAMPLE_TIMELINE_EVENTS[3]
        self._build_ui()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 12, 16, 12)
        main_layout.setSpacing(10)

        # 1. Top Sub-Header Bar
        header_box = QHBoxLayout()
        header_box.setSpacing(12)

        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)

        subtitle_lbl = QLabel("INVESTIGATION TIMELINE")
        subtitle_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B; letter-spacing: 0.5px;")
        title_layout.addWidget(subtitle_lbl)

        counts_row = QHBoxLayout()
        counts_row.setSpacing(8)

        cnt_lbl = QLabel("16 events")
        cnt_lbl.setStyleSheet("font-size: 16px; font-weight: 800; color: #F8FAFC;")
        counts_row.addWidget(cnt_lbl)

        dot_lbl = QLabel("·")
        dot_lbl.setStyleSheet("color: #64748B; font-weight: 700;")
        counts_row.addWidget(dot_lbl)

        date_lbl = QLabel("Nov 15, 2024")
        date_lbl.setStyleSheet("font-size: 14px; font-weight: 600; color: #94A3B8;")
        counts_row.addWidget(date_lbl)

        title_layout.addLayout(counts_row)
        header_box.addLayout(title_layout)

        header_box.addStretch()

        range_lbl = QLabel("07:45:00  ─────────  07:54:33")
        range_lbl.setStyleSheet("font-family: monospace; font-size: 12px; color: #64748B; font-weight: 600;")
        header_box.addWidget(range_lbl)

        main_layout.addLayout(header_box)

        # 2. Category & Severity Filter Rows
        filter_layout = QVBoxLayout()
        filter_layout.setSpacing(6)

        # Row 1: TYPE Filter Chips
        type_row = QHBoxLayout()
        type_row.setSpacing(6)

        type_hdr = QLabel("TYPE")
        type_hdr.setStyleSheet("font-size: 10px; font-weight: 700; color: #64748B; min-width: 32px;")
        type_row.addWidget(type_hdr)

        type_filters = [
            ("⬡ Process", True),
            ("# Network", False),
            ("= File", False),
            ("⬚ Registry", False),
            ("⚠️ Finding", False),
            ("▶ Plugin", False),
            ("↓ Acquisition", False),
        ]
        for name, active in type_filters:
            btn = QPushButton(name)
            if active:
                btn.setStyleSheet(
                    "background: #1E293B; border: 1px solid #3B82F6; color: #38BDF8; "
                    "font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 4px;"
                )
            else:
                btn.setStyleSheet(
                    "background: #0F172A; border: 1px solid #1E293B; color: #94A3B8; "
                    "font-size: 11px; font-weight: 500; padding: 3px 10px; border-radius: 4px;"
                )
            type_row.addWidget(btn)

        type_row.addStretch()
        filter_layout.addLayout(type_row)

        # Row 2: SEV Filter Chips
        sev_row = QHBoxLayout()
        sev_row.setSpacing(6)

        sev_hdr = QLabel("SEV")
        sev_hdr.setStyleSheet("font-size: 10px; font-weight: 700; color: #64748B; min-width: 32px;")
        sev_row.addWidget(sev_hdr)

        sev_filters = [("Critical", True), ("High", False), ("Medium", False), ("Low", False), ("Info", False)]
        for name, active in sev_filters:
            btn = QPushButton(name)
            if active:
                btn.setStyleSheet(
                    "background: #450A0A; border: 1px solid #EF4444; color: #F87171; "
                    "font-size: 11px; font-weight: 600; padding: 3px 10px; border-radius: 4px;"
                )
            else:
                btn.setStyleSheet(
                    "background: #0F172A; border: 1px solid #1E293B; color: #94A3B8; "
                    "font-size: 11px; font-weight: 500; padding: 3px 10px; border-radius: 4px;"
                )
            sev_row.addWidget(btn)

        sev_row.addStretch()
        filter_layout.addLayout(sev_row)

        main_layout.addLayout(filter_layout)

        # 3. Main Splitter (Left: Timeline Stream, Right: Event Detail Panel)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background: #1E293B; width: 1px; }")

        # Left Column: Event Stream Scroll Area
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        scroll_stream = QScrollArea()
        scroll_stream.setWidgetResizable(True)
        scroll_stream.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        stream_container = QWidget()
        stream_box = QVBoxLayout(stream_container)
        stream_box.setContentsMargins(0, 0, 8, 0)
        stream_box.setSpacing(10)

        for data in SAMPLE_TIMELINE_EVENTS:
            card = TimelineCardWidget(data)
            card.clicked.connect(self._on_event_clicked)
            self.cards_map[data["id"]] = card
            stream_box.addWidget(card)

        stream_box.addStretch()
        scroll_stream.setWidget(stream_container)
        left_layout.addWidget(scroll_stream)

        splitter.addWidget(left_widget)

        # Right Column: Event Detail Panel
        right_panel = QFrame()
        right_panel.setFixedWidth(320)
        right_panel.setStyleSheet("background: #0D1322; border: 1px solid #1E293B; border-radius: 6px;")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(16, 16, 16, 16)
        right_layout.setSpacing(14)

        insp_hdr = QLabel("EVENT DETAIL")
        insp_hdr.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B; letter-spacing: 0.5px;")
        right_layout.addWidget(insp_hdr)

        # Event Badges Row
        badges_row = QHBoxLayout()
        badges_row.setSpacing(8)

        self.detail_type_badge = create_badge_label("Process", "blue")
        badges_row.addWidget(self.detail_type_badge)

        self.detail_sev_lbl = QLabel("CRITICAL")
        self.detail_sev_lbl.setStyleSheet("font-size: 11px; font-weight: 800; color: #EF4444;")
        badges_row.addWidget(self.detail_sev_lbl)

        badges_row.addStretch()
        right_layout.addLayout(badges_row)

        # Event Title
        self.detail_title_lbl = QLabel("powershell.exe (PID 9248) spawned by WINWORD.EXE")
        self.detail_title_lbl.setStyleSheet("font-size: 15px; font-weight: 800; color: #F8FAFC;")
        self.detail_title_lbl.setWordWrap(True)
        right_layout.addWidget(self.detail_title_lbl)

        # Key-Value Grid Inspector Box
        kv_frame = QFrame()
        kv_frame.setStyleSheet("background: #080C14; border: 1px solid #1E293B; border-radius: 4px;")
        kv_box = QVBoxLayout(kv_frame)
        kv_box.setContentsMargins(12, 10, 12, 10)
        kv_box.setSpacing(8)

        self.kv_timestamp = self._add_kv_row(kv_box, "Timestamp", "2024-11-15 07:47:31")
        self.kv_artifact = self._add_kv_row(kv_box, "Artifact", "PID:9248")
        self.kv_type = self._add_kv_row(kv_box, "Type", "process")
        self.kv_sev = self._add_kv_row(kv_box, "Severity", "critical", is_crit=True)

        right_layout.addWidget(kv_frame)

        # Monospace Command Line / Detail Box
        self.detail_box_frame = QFrame()
        self.detail_box_frame.setStyleSheet("background: #080C14; border: 1px solid #1E293B; border-radius: 4px;")
        db_layout = QVBoxLayout(self.detail_box_frame)
        db_layout.setContentsMargins(12, 10, 12, 10)

        self.detail_text_lbl = QLabel("Encoded command line (-enc)")
        self.detail_text_lbl.setWordWrap(True)
        self.detail_text_lbl.setStyleSheet(
            "font-family: monospace; font-size: 11px; color: #94A3B8; line-height: 1.4;"
        )
        db_layout.addWidget(self.detail_text_lbl)

        right_layout.addWidget(self.detail_box_frame)

        right_layout.addStretch()

        # Floating Alert Banner
        alert_banner = QFrame()
        alert_banner.setStyleSheet("background: #0F172A; border: 1px solid #334155; border-radius: 6px;")
        alert_box = QHBoxLayout(alert_banner)
        alert_box.setContentsMargins(12, 8, 12, 8)

        warn_icon = QLabel("⚠️")
        warn_icon.setStyleSheet("font-size: 12px;")
        alert_box.addWidget(warn_icon)

        alert_msg = QLabel("Live preview failed ID: srid_8HA9Z7BYX247RY565JHN507R")
        alert_msg.setStyleSheet("color: #E2E8F0; font-size: 10px; font-weight: 600; font-family: monospace;")
        alert_box.addWidget(alert_msg)

        alert_box.addStretch()

        retry_btn = QPushButton("Retry")
        retry_btn.setStyleSheet(
            "background: #1E293B; border: 1px solid #475569; color: #F8FAFC; "
            "font-size: 10px; font-weight: 600; padding: 2px 8px; border-radius: 3px;"
        )
        alert_box.addWidget(retry_btn)

        right_layout.addWidget(alert_banner)

        # Quick Actions Section
        act_hdr = QLabel("Actions")
        act_hdr.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B;")
        right_layout.addWidget(act_hdr)

        act_box = QVBoxLayout()
        act_box.setSpacing(6)

        btn_artifact = QPushButton("▶  View Artifact")
        btn_artifact.setStyleSheet(
            "background: #172554; border: 1px solid #1D4ED8; color: #60A5FA; "
            "font-size: 12px; font-weight: 600; padding: 8px; border-radius: 4px; text-align: left;"
        )
        btn_artifact.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_artifact.clicked.connect(self.open_evidence_explorer_requested.emit)
        act_box.addWidget(btn_artifact)

        btn_graph = QPushButton("▶  Show in Graph")
        btn_graph.setStyleSheet(
            "background: #172554; border: 1px solid #1D4ED8; color: #60A5FA; "
            "font-size: 12px; font-weight: 600; padding: 8px; border-radius: 4px; text-align: left;"
        )
        btn_graph.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_graph.clicked.connect(self.open_relationship_graph_requested.emit)
        act_box.addWidget(btn_graph)

        right_layout.addLayout(act_box)

        splitter.addWidget(right_panel)
        splitter.setSizes([650, 350])

        main_layout.addWidget(splitter, stretch=1)

        # Select EVT-004 initially
        self._on_event_clicked("EVT-004")

    def _add_kv_row(self, container: QVBoxLayout, key: str, val: str, is_crit: bool = False) -> QLabel:
        row = QHBoxLayout()

        k_lbl = QLabel(key)
        k_lbl.setStyleSheet("font-size: 11px; color: #64748B; font-weight: 500;")
        row.addWidget(k_lbl)

        row.addStretch()

        v_lbl = QLabel(val)
        if is_crit:
            v_lbl.setStyleSheet("font-family: monospace; font-size: 11px; color: #EF4444; font-weight: 700;")
        else:
            v_lbl.setStyleSheet("font-family: monospace; font-size: 11px; color: #E2E8F0; font-weight: 600;")
        row.addWidget(v_lbl)

        container.addLayout(row)
        return v_lbl

    def _on_event_clicked(self, event_id: str) -> None:
        for eid, card in self.cards_map.items():
            card.set_selected(eid == event_id)

        event = next((e for e in SAMPLE_TIMELINE_EVENTS if e["id"] == event_id), None)
        if not event:
            return

        self.selected_event = event

        # Update Inspector Right Panel
        self.detail_type_badge.setText(event["category_label"])
        self.detail_sev_lbl.setText(event["severity"].upper())
        if event["severity"] == "critical":
            self.detail_sev_lbl.setStyleSheet("font-size: 11px; font-weight: 800; color: #EF4444;")
        elif event["severity"] == "high":
            self.detail_sev_lbl.setStyleSheet("font-size: 11px; font-weight: 800; color: #F59E0B;")
        else:
            self.detail_sev_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #94A3B8;")

        self.detail_title_lbl.setText(event["title"])
        self.kv_timestamp.setText(event["timestamp_full"])
        self.kv_artifact.setText(event["artifact"])
        self.kv_type.setText(event["type"])
        self.kv_sev.setText(event["severity"])

        self.detail_text_lbl.setText(event["details_box"])

    def set_active_case(self, case: Case | None) -> None:
        """Propagate active case to view."""
        self.active_case = case
