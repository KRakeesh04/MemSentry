"""Analysis & Plugin Center view widget for configuring, running, and reviewing forensic analysis runs."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any
from uuid import UUID

from PySide6.QtCore import QObject, Qt, QThread, QTimer, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QShowEvent
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from memsentry.analysis.orchestrator import AnalysisOrchestrator
from memsentry.gui.theme import create_badge_label
from memsentry.models.analysis_run import (
    AnalysisRun,
    AnalysisRunCreate,
    HostOS,
)
from memsentry.models.case import Case
from memsentry.models.evidence import Evidence
from memsentry.models.plugin_run import PluginRun, PluginRunCreate
from memsentry.storage.repositories.analysis_run_repository import AnalysisRunRepository
from memsentry.storage.repositories.evidence_repository import EvidenceRepository
from memsentry.storage.repositories.plugin_run_repository import PluginRunRepository
from memsentry.version import __version__
from memsentry.volatility.plugin_applicability import (
    PluginApplicabilityService,
    PluginMetadata,
)


def get_current_host_os() -> HostOS:
    """Detect current operating system hosting MemSentry."""
    sys_plat = sys.platform.lower()
    if sys_plat.startswith("win"):
        return HostOS.WINDOWS
    if sys_plat.startswith("linux"):
        return HostOS.LINUX
    if sys_plat.startswith("darwin"):
        return HostOS.MACOS
    return HostOS.WINDOWS


class AnalysisWorker(QThread):
    """Background worker thread for running AnalysisOrchestrator without blocking the GUI event loop."""

    finished = Signal(object)  # Emits AnalysisRun model on completion
    failed = Signal(str)      # Emits error message string on failure

    def __init__(
        self,
        orchestrator: AnalysisOrchestrator,
        analysis_run_id: UUID,
        parent: QObject | None = None,
    ) -> None:
        super().__init__(parent)
        self.orchestrator = orchestrator
        self.analysis_run_id = analysis_run_id

    def run(self) -> None:
        try:
            result = self.orchestrator.execute_analysis_run(self.analysis_run_id)
            self.finished.emit(result)
        except Exception as exc:
            self.failed.emit(str(exc))


SAMPLE_PLUGIN_DETAILS: dict[str, dict[str, Any]] = {
    "windows.pstree": {
        "title": "Process Tree",
        "identifier": "windows.pstree",
        "status": "Completed",
        "os": "Windows",
        "category": "Processes",
        "description": "Displays process execution hierarchy in a tree structure using parent-child PID links.",
        "results": 19,
        "duration": "1.2s",
    },
    "windows.pslist": {
        "title": "Process List",
        "identifier": "windows.pslist",
        "status": "Completed",
        "os": "Windows",
        "category": "Processes",
        "description": "Lists active processes by walking the doubly-linked ActiveProcessLinks list in Executive Process Blocks (EPROCESS).",
        "results": 184,
        "duration": "0.8s",
    },
    "windows.psscan": {
        "title": "Process Scanner",
        "identifier": "windows.psscan",
        "status": "Completed",
        "os": "Windows",
        "category": "Processes",
        "description": "Scans physical memory pool tags for terminated, unlinked, or hidden EPROCESS structures.",
        "results": 189,
        "duration": "4.1s",
    },
    "windows.cmdline": {
        "title": "Command Lines",
        "identifier": "windows.cmdline",
        "status": "Completed",
        "os": "Windows",
        "category": "Processes",
        "description": "Extracts process command line arguments and environment variables from PEB ProcessParameters.",
        "results": 47,
        "duration": "1.4s",
    },
    "windows.netstat": {
        "title": "Network Connections",
        "identifier": "windows.netstat",
        "status": "Completed",
        "os": "Windows",
        "category": "Network",
        "description": "Scans network socket structures to identify active, listening, or closed TCP/UDP connections.",
        "results": 23,
        "duration": "0.6s",
    },
    "windows.netscan": {
        "title": "Network Scanner",
        "identifier": "windows.netscan",
        "status": "Completed",
        "os": "Windows",
        "category": "Network",
        "description": "Pool scans physical memory for historical network socket and endpoint structures.",
        "results": 31,
        "duration": "2.1s",
    },
    "windows.dlllist": {
        "title": "Loaded DLLs",
        "identifier": "windows.dlllist",
        "status": "Completed",
        "os": "Windows",
        "category": "Modules",
        "description": "Lists loaded dynamic link libraries (DLLs) for each process from PEB InLoadOrderModuleList.",
        "results": 2847,
        "duration": "3.4s",
    },
    "windows.malfind": {
        "title": "Malware Finder",
        "identifier": "windows.malfind",
        "status": "Completed",
        "os": "Windows",
        "category": "Memory Analysis",
        "description": "Find injected code and RWX memory regions using VAD and PEB metadata",
        "results": 6,
        "duration": "18.7s",
    },
}


class AnalysisPluginCardWidget(QFrame):
    """Custom card for individual plugins in the Analysis Plugin Center list."""

    clicked = Signal(str)

    def __init__(self, p_id: str, p_title: str, p_res: int, p_dur: str, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.plugin_id = p_id
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setStyleSheet(
            "QFrame { background: #0D1322; border: 1px solid #1E293B; border-radius: 6px; } "
            "QFrame:hover { background: #151D30; border-color: #334155; }"
        )
        card_box = QHBoxLayout(self)
        card_box.setContentsMargins(14, 12, 14, 12)

        dot_lbl = QLabel("●")
        dot_lbl.setStyleSheet("color: #10B981; font-size: 12px; margin-right: 4px;")
        card_box.addWidget(dot_lbl)

        info_box = QVBoxLayout()
        info_box.setSpacing(2)

        t_lbl = QLabel(p_title)
        t_lbl.setStyleSheet("font-size: 13px; font-weight: 700; color: #F8FAFC;")
        id_sub = QLabel(p_id)
        id_sub.setStyleSheet("font-family: monospace; font-size: 11px; color: #64748B;")

        info_box.addWidget(t_lbl)
        info_box.addWidget(id_sub)
        card_box.addLayout(info_box)

        card_box.addStretch()

        stats_lbl = QLabel(f"<b>{p_res:,}</b> <span style='color:#64748B;'>results</span> &nbsp; <span style='color:#94A3B8;'>{p_dur}</span>")
        stats_lbl.setTextFormat(Qt.TextFormat.RichText)
        stats_lbl.setStyleSheet("font-size: 12px; color: #E2E8F0;")
        card_box.addWidget(stats_lbl)

    def mousePressEvent(self, event: object) -> None:
        self.clicked.emit(self.plugin_id)


class AnalysisView(QWidget):
    """View widget for configuring plugins, executing analysis runs, and reviewing run status history."""

    open_evidence_explorer_requested = Signal()

    def __init__(
        self,
        evidence_repository: EvidenceRepository,
        analysis_run_repository: AnalysisRunRepository,
        plugin_run_repository: PluginRunRepository,
        plugin_applicability_service: type[
            PluginApplicabilityService
        ] = PluginApplicabilityService,
        analysis_orchestrator: AnalysisOrchestrator | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("AnalysisView")
        self.evidence_repository = evidence_repository
        self.analysis_run_repository = analysis_run_repository
        self.plugin_run_repository = plugin_run_repository
        self.plugin_applicability_service = plugin_applicability_service
        self.analysis_orchestrator = analysis_orchestrator

        self.active_case: Case | None = None
        self.selected_evidence: Evidence | None = None
        self.evidence_records: list[Evidence] = []
        self.analysis_worker: AnalysisWorker | None = None
        self.current_running_analysis_id: UUID | None = None

        self.status_poll_timer = QTimer(self)
        self.status_poll_timer.setInterval(500)
        self.status_poll_timer.timeout.connect(self._poll_running_analysis_status)

        self._build_ui()
        self.update_case_state()

    def _build_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 12, 16, 12)
        main_layout.setSpacing(12)

        # 1. Top Sub-Header Bar
        header_box = QHBoxLayout()
        header_box.setSpacing(12)

        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)

        self.subtitle_label = QLabel("ANALYSIS  ·  PLUGIN CENTER")
        self.subtitle_label.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B; letter-spacing: 0.5px;")
        title_layout.addWidget(self.subtitle_label)

        status_summary_row = QHBoxLayout()
        status_summary_row.setSpacing(12)

        self.title_label = QLabel("14 completed")
        self.title_label.setStyleSheet("font-size: 15px; font-weight: 800; color: #10B981;")
        status_summary_row.addWidget(self.title_label)

        c_run = QLabel("1 running")
        c_run.setStyleSheet("font-size: 14px; font-weight: 700; color: #38BDF8;")
        status_summary_row.addWidget(c_run)

        c_que = QLabel("2 queued")
        c_que.setStyleSheet("font-size: 14px; font-weight: 600; color: #94A3B8;")
        status_summary_row.addWidget(c_que)

        title_layout.addLayout(status_summary_row)
        header_box.addLayout(title_layout)

        header_box.addStretch()

        # Evidence Target Selector Combo (Compact)
        picker_box = QHBoxLayout()
        picker_lbl = QLabel("Target Image:")
        picker_lbl.setStyleSheet("font-size: 12px; font-weight: 600; color: #94A3B8;")
        picker_box.addWidget(picker_lbl)

        self.evidence_combo = QComboBox()
        self.evidence_combo.setFixedWidth(240)
        self.evidence_combo.setStyleSheet(
            "background: #1E293B; border: 1px solid #334155; color: #F8FAFC; "
            "padding: 4px 8px; border-radius: 4px; font-size: 12px;"
        )
        self.evidence_combo.currentIndexChanged.connect(self.on_evidence_changed)
        picker_box.addWidget(self.evidence_combo)
        header_box.addLayout(picker_box)

        # Run All Queued Action Button
        self.run_button = QPushButton("⚡ Run All Queued")
        self.run_button.setObjectName("primaryButton")
        self.run_button.setStyleSheet(
            "background: #1D4ED8; border: 1px solid #2563EB; color: #F8FAFC; "
            "font-size: 13px; font-weight: 700; padding: 6px 18px; border-radius: 4px;"
        )
        self.run_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.run_button.clicked.connect(self.run_analysis)
        header_box.addWidget(self.run_button)

        main_layout.addLayout(header_box)

        # OS & Category Filter Chips Bar
        filter_layout = QVBoxLayout()
        filter_layout.setSpacing(6)

        filter_row = QHBoxLayout()
        filter_row.setSpacing(8)

        # OS Chips
        os_win_btn = QPushButton("Windows")
        os_win_btn.setStyleSheet(
            "background: #1E293B; border: 1px solid #3B82F6; color: #38BDF8; "
            "font-size: 12px; font-weight: 700; padding: 4px 14px; border-radius: 4px;"
        )
        filter_row.addWidget(os_win_btn)

        os_lin_btn = QPushButton("Linux")
        os_lin_btn.setStyleSheet(
            "background: #0F172A; border: 1px solid #1E293B; color: #94A3B8; "
            "font-size: 12px; font-weight: 500; padding: 4px 14px; border-radius: 4px;"
        )
        filter_row.addWidget(os_lin_btn)

        sep_lbl = QLabel("|")
        sep_lbl.setStyleSheet("color: #334155; font-weight: 700;")
        filter_row.addWidget(sep_lbl)

        categories = [
            "Processes",
            "Network",
            "Modules",
            "Memory Analysis",
            "Objects",
            "Registry",
            "Services",
            "Kernel",
        ]
        for cat in categories:
            btn = QPushButton(cat)
            btn.setStyleSheet(
                "background: transparent; color: #94A3B8; font-size: 12px; font-weight: 500; padding: 4px 8px;"
            )
            filter_row.addWidget(btn)

        filter_row.addStretch()
        filter_layout.addLayout(filter_row)
        main_layout.addLayout(filter_layout)

        # Hidden / Compatibility UI Labels & Buttons
        self.evidence_info_card = QLabel("No evidence selected")
        self.evidence_info_card.hide()
        main_layout.addWidget(self.evidence_info_card)

        self.state_label = QLabel()
        self.state_label.setStyleSheet("color: #38BDF8; font-size: 11px; font-weight: 600;")
        main_layout.addWidget(self.state_label)

        self.plugins_status_label = QLabel()
        self.plugins_status_label.hide()

        self.select_all_btn = QPushButton("Select All")
        self.select_all_btn.hide()
        self.select_all_btn.clicked.connect(self.select_all_plugins)

        self.deselect_all_btn = QPushButton("Deselect All")
        self.deselect_all_btn.hide()
        self.deselect_all_btn.clicked.connect(self.deselect_all_plugins)

        self.plugins_list = QListWidget()
        self.plugins_list.hide()

        # 2. Main Center Splitter (Left: Categorized Plugin Cards, Right: Plugin Detail Inspector)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background: #1E293B; width: 1px; }")

        # Left Column: Plugin Cards Stream
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(10)

        scroll_cards = QScrollArea()
        scroll_cards.setWidgetResizable(True)
        scroll_cards.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        cards_container = QWidget()
        self.cards_box = QVBoxLayout(cards_container)
        self.cards_box.setContentsMargins(0, 0, 8, 0)
        self.cards_box.setSpacing(12)

        self._populate_figma_plugin_cards()

        scroll_cards.setWidget(cards_container)
        left_layout.addWidget(scroll_cards)
        splitter.addWidget(left_widget)

        # Right Column: Plugin Detail Panel
        right_panel = QFrame()
        right_panel.setFixedWidth(340)
        right_panel.setStyleSheet("background: #0D1322; border: 1px solid #1E293B; border-radius: 6px;")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(18, 18, 18, 18)
        right_layout.setSpacing(14)

        insp_hdr = QLabel("PLUGIN DETAIL")
        insp_hdr.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B; letter-spacing: 0.5px;")
        right_layout.addWidget(insp_hdr)

        self.detail_plugin_title = QLabel("Malware Finder")
        self.detail_plugin_title.setStyleSheet("font-size: 20px; font-weight: 800; color: #F8FAFC;")
        right_layout.addWidget(self.detail_plugin_title)

        # Badges Row
        badges_row = QHBoxLayout()
        badges_row.setSpacing(6)

        self.detail_status_badge = create_badge_label("Completed", "info")
        self.detail_status_badge.setStyleSheet(
            "background: #064E3B; color: #34D399; font-size: 11px; font-weight: 700; border-radius: 4px; padding: 3px 8px;"
        )
        badges_row.addWidget(self.detail_status_badge)

        os_badge = create_badge_label("Windows", "gray")
        os_badge.setStyleSheet(
            "background: #1E293B; color: #94A3B8; font-size: 11px; font-weight: 600; border-radius: 4px; padding: 3px 8px;"
        )
        badges_row.addWidget(os_badge)

        self.detail_cat_badge = create_badge_label("Memory Analysis", "gray")
        self.detail_cat_badge.setStyleSheet(
            "background: #1E293B; color: #94A3B8; font-size: 11px; font-weight: 600; border-radius: 4px; padding: 3px 8px;"
        )
        badges_row.addWidget(self.detail_cat_badge)
        badges_row.addStretch()

        right_layout.addLayout(badges_row)

        # Plugin Identifier Box
        id_frame = QFrame()
        id_frame.setStyleSheet("background: #080C14; border: 1px solid #1E293B; border-radius: 4px;")
        id_box = QVBoxLayout(id_frame)
        id_box.setContentsMargins(12, 10, 12, 10)
        id_box.setSpacing(4)

        id_lbl = QLabel("PLUGIN IDENTIFIER")
        id_lbl.setStyleSheet("font-size: 10px; font-weight: 700; color: #64748B;")
        id_box.addWidget(id_lbl)

        self.detail_id_val = QLabel("windows.malfind")
        self.detail_id_val.setStyleSheet("font-family: monospace; font-size: 13px; font-weight: 700; color: #60A5FA;")
        id_box.addWidget(self.detail_id_val)

        right_layout.addWidget(id_frame)

        # Description Section
        desc_hdr = QLabel("Description")
        desc_hdr.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B;")
        right_layout.addWidget(desc_hdr)

        self.detail_desc_lbl = QLabel("Find injected code and RWX memory regions using VAD and PEB metadata")
        self.detail_desc_lbl.setWordWrap(True)
        self.detail_desc_lbl.setStyleSheet("font-size: 13px; color: #94A3B8; line-height: 1.4;")
        right_layout.addWidget(self.detail_desc_lbl)

        # Stats Cards Row (Results & Duration)
        stats_row = QHBoxLayout()
        stats_row.setSpacing(10)

        # Results Card
        res_card = QFrame()
        res_card.setStyleSheet("background: #080C14; border: 1px solid #1E293B; border-radius: 6px;")
        res_box = QVBoxLayout(res_card)
        res_box.setContentsMargins(12, 10, 12, 10)
        res_box.setSpacing(4)

        res_lbl = QLabel("RESULTS")
        res_lbl.setStyleSheet("font-size: 10px; font-weight: 700; color: #64748B;")
        res_box.addWidget(res_lbl)

        self.detail_results_val = QLabel("6")
        self.detail_results_val.setStyleSheet("font-size: 22px; font-weight: 800; color: #F8FAFC;")
        res_box.addWidget(self.detail_results_val)

        stats_row.addWidget(res_card, stretch=1)

        # Duration Card
        dur_card = QFrame()
        dur_card.setStyleSheet("background: #080C14; border: 1px solid #1E293B; border-radius: 6px;")
        dur_box = QVBoxLayout(dur_card)
        dur_box.setContentsMargins(12, 10, 12, 10)
        dur_box.setSpacing(4)

        dur_lbl = QLabel("DURATION")
        dur_lbl.setStyleSheet("font-size: 10px; font-weight: 700; color: #64748B;")
        dur_box.addWidget(dur_lbl)

        self.detail_duration_val = QLabel("18.7s")
        self.detail_duration_val.setStyleSheet("font-size: 22px; font-weight: 800; color: #F8FAFC;")
        dur_box.addWidget(self.detail_duration_val)

        stats_row.addWidget(dur_card, stretch=1)

        right_layout.addLayout(stats_row)
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

        # Actions Section
        act_hdr = QLabel("Actions")
        act_hdr.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B;")
        right_layout.addWidget(act_hdr)

        act_box = QVBoxLayout()
        act_box.setSpacing(6)

        btn_view_ws = QPushButton("▶  View Results in Workspace")
        btn_view_ws.setStyleSheet(
            "background: #172554; border: 1px solid #1D4ED8; color: #60A5FA; "
            "font-size: 12px; font-weight: 600; padding: 8px; border-radius: 4px; text-align: left;"
        )
        btn_view_ws.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_view_ws.clicked.connect(self.open_evidence_explorer_requested.emit)
        act_box.addWidget(btn_view_ws)

        self.view_output_btn = QPushButton("↗  Export Results")
        self.view_output_btn.setStyleSheet(
            "background: #1E293B; border: 1px solid #334155; color: #E2E8F0; "
            "font-size: 12px; font-weight: 600; padding: 8px; border-radius: 4px; text-align: left;"
        )
        self.view_output_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self.view_output_btn.clicked.connect(self.open_selected_plugin_output)
        act_box.addWidget(self.view_output_btn)

        right_layout.addLayout(act_box)

        splitter.addWidget(right_panel)
        splitter.setSizes([650, 350])

        main_layout.addWidget(splitter, stretch=1)

        # Hidden Analysis & Plugin Run Tables for Compatibility
        self.runs_table = QTableWidget(0, 5)
        self.runs_table.hide()
        self.runs_table.itemSelectionChanged.connect(self.on_analysis_run_selected)

        self.plugin_runs_table = QTableWidget(0, 4)
        self.plugin_runs_table.hide()
        self.plugin_runs_table.itemSelectionChanged.connect(self.on_plugin_run_selected)

        # Initial detail populate
        self._select_plugin_detail("windows.malfind")


    def _populate_figma_plugin_cards(self) -> None:
        categories = [
            ("PROCESSES", [
                ("windows.pstree", "Process Tree", 19, "1.2s"),
                ("windows.pslist", "Process List", 184, "0.8s"),
                ("windows.psscan", "Process Scanner", 189, "4.1s"),
                ("windows.cmdline", "Command Lines", 47, "1.4s"),
            ]),
            ("NETWORK", [
                ("windows.netstat", "Network Connections", 23, "0.6s"),
                ("windows.netscan", "Network Scanner", 31, "2.1s"),
            ]),
            ("MODULES", [
                ("windows.dlllist", "Loaded DLLs", 2847, "3.4s"),
            ]),
        ]

        for cat_name, plugin_items in categories:
            cat_lbl = QLabel(cat_name)
            cat_lbl.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B; letter-spacing: 0.5px; margin-top: 4px;")
            self.cards_box.addWidget(cat_lbl)

            for p_id, p_title, p_res, p_dur in plugin_items:
                card = AnalysisPluginCardWidget(p_id, p_title, p_res, p_dur)
                card.clicked.connect(self._select_plugin_detail)
                self.cards_box.addWidget(card)

    def _select_plugin_detail(self, plugin_id: str) -> None:
        info = SAMPLE_PLUGIN_DETAILS.get(plugin_id, SAMPLE_PLUGIN_DETAILS["windows.malfind"])
        self.detail_plugin_title.setText(info["title"])
        self.detail_id_val.setText(info["identifier"])
        self.detail_desc_lbl.setText(info["description"])
        self.detail_results_val.setText(f"{info['results']:,}")
        self.detail_duration_val.setText(info["duration"])
        self.detail_cat_badge.setText(info["category"])

    def set_active_case(self, case: Case | None) -> None:
        """Set active case context and update evidence items."""
        self.active_case = case
        self.update_case_state()

    def update_case_state(self) -> None:
        """Update UI based on active case presence."""
        self.evidence_combo.blockSignals(True)
        self.evidence_combo.clear()
        self.evidence_records.clear()
        self.selected_evidence = None

        if self.active_case is None:
            self.evidence_combo.setEnabled(False)
            self.state_label.setText(
                "No case opened. Select or open a case to configure and view analysis."
            )
            self.clear_all_views()
            self.evidence_combo.blockSignals(False)
            return

        self.evidence_combo.setEnabled(True)
        self.load_evidence_for_case()
        self.evidence_combo.blockSignals(False)

    def showEvent(self, event: QShowEvent) -> None:
        """Refresh evidence list whenever AnalysisView is shown."""
        super().showEvent(event)
        if self.active_case is not None:
            self.load_evidence_for_case()

    def load_evidence_for_case(self) -> None:
        """Fetch registered evidence files for the active case."""
        if self.active_case is None:
            return

        self.evidence_combo.blockSignals(True)
        self.evidence_combo.clear()
        self.evidence_records.clear()
        self.selected_evidence = None

        self.state_label.setText("Loading evidence for case...")
        try:
            records = self.evidence_repository.list_by_case(self.active_case.id)
        except Exception as exc:
            self.state_label.setText(f"Unable to load evidence: {exc}")
            self.clear_all_views()
            self.evidence_combo.blockSignals(False)
            return

        self.evidence_records = records

        if not records:
            self.state_label.setText(
                "No evidence registered for this case yet. Register evidence in the Evidence tab first."
            )
            self.clear_all_views()
            self.evidence_combo.blockSignals(False)
            return

        self.state_label.setText(f"{len(records)} evidence file(s) available")
        for evidence in records:
            os_str = (
                evidence.evidence_os.value.capitalize()
                if evidence.evidence_os is not None
                else "Unknown"
            )
            label = f"{evidence.original_filename} ({os_str}, {evidence.file_size_bytes:,} B)"
            self.evidence_combo.addItem(label, evidence)

        self.evidence_combo.blockSignals(False)

        if self.evidence_combo.count() > 0:
            self.evidence_combo.setCurrentIndex(0)
            self.on_evidence_changed()

    def on_evidence_changed(self) -> None:
        """Handle change in evidence combo selection."""
        data = self.evidence_combo.currentData()
        if isinstance(data, Evidence):
            self.selected_evidence = data
            self.display_evidence_info(data)
            self.populate_applicable_plugins(data)
            self.load_analysis_history(data)
        else:
            self.selected_evidence = None
            self.clear_all_views()

    def display_evidence_info(self, evidence: Evidence) -> None:
        """Display summary card for the selected evidence file."""
        os_str = (
            evidence.evidence_os.value.capitalize()
            if evidence.evidence_os is not None
            else "Unknown"
        )
        self.evidence_info_card.setText(
            f"<b>Evidence:</b> {evidence.original_filename} | "
            f"<b>OS:</b> {os_str} | "
            f"<b>Size:</b> {evidence.file_size_bytes:,} bytes | "
            f"<b>Integrity:</b> {evidence.integrity_status.value.capitalize()} | "
            f"<b>SHA-256:</b> {evidence.sha256[:16]}..."
        )

    def populate_applicable_plugins(self, evidence: Evidence) -> None:
        """Populate checkable plugins list based on target OS."""
        self.plugins_list.clear()

        if evidence.evidence_os is None:
            self.plugins_status_label.setText(
                "Target OS is unknown. Select an OS for this evidence to configure plugins."
            )
            self.run_button.setEnabled(False)
            self.select_all_btn.setEnabled(False)
            self.deselect_all_btn.setEnabled(False)
            return

        plugins: list[PluginMetadata] = (
            self.plugin_applicability_service.get_available_plugins(
                evidence.evidence_os
            )
        )

        if not plugins:
            self.plugins_status_label.setText(
                f"No core plugins available for {evidence.evidence_os.value.capitalize()}."
            )
            self.run_button.setEnabled(False)
            self.select_all_btn.setEnabled(False)
            self.deselect_all_btn.setEnabled(False)
            return

        self.plugins_status_label.setText(
            f"Available Core Plugins ({len(plugins)}) for {evidence.evidence_os.value.capitalize()}:"
        )
        self.select_all_btn.setEnabled(True)
        self.deselect_all_btn.setEnabled(True)
        self.run_button.setEnabled(True)

        for plugin in plugins:
            item_text = (
                f"[{plugin.category.value.upper()}] {plugin.name} — {plugin.description}"
            )
            list_item = QListWidgetItem(item_text)
            list_item.setFlags(
                list_item.flags() | Qt.ItemFlag.ItemIsUserCheckable
            )
            list_item.setCheckState(Qt.CheckState.Checked)
            list_item.setData(Qt.ItemDataRole.UserRole, plugin)
            self.plugins_list.addItem(list_item)

    def select_all_plugins(self) -> None:
        for index in range(self.plugins_list.count()):
            item = self.plugins_list.item(index)
            if item is not None:
                item.setCheckState(Qt.CheckState.Checked)

    def deselect_all_plugins(self) -> None:
        for index in range(self.plugins_list.count()):
            item = self.plugins_list.item(index)
            if item is not None:
                item.setCheckState(Qt.CheckState.Unchecked)

    def get_selected_plugin_names(self) -> list[str]:
        """Return names of plugins currently checked in the list."""
        selected_names: list[str] = []
        for index in range(self.plugins_list.count()):
            item = self.plugins_list.item(index)
            if item is not None and item.checkState() == Qt.CheckState.Checked:
                plugin = item.data(Qt.ItemDataRole.UserRole)
                if isinstance(plugin, PluginMetadata):
                    selected_names.append(plugin.name)
        return selected_names

    def run_analysis(self) -> None:
        """Stage pending AnalysisRun/PluginRun records and launch AnalysisWorker background thread."""
        if self.selected_evidence is None:
            self.state_label.setText("Please select an evidence file.")
            return

        if self.analysis_worker is not None and self.analysis_worker.isRunning():
            self.state_label.setText("An analysis run is already in progress.")
            return

        selected_plugins = self.get_selected_plugin_names()
        if not selected_plugins:
            self.state_label.setText(
                "Please select at least one plugin to include in the analysis run."
            )
            return

        try:
            host_os = get_current_host_os()
            analysis_create = AnalysisRunCreate(
                evidence_id=self.selected_evidence.id,
                application_version=__version__,
                volatility_version="3.0.0",
                host_os=host_os,
            )
            analysis_run = self.analysis_run_repository.create(analysis_create)

            for plugin_name in selected_plugins:
                plugin_create = PluginRunCreate(
                    analysis_run_id=analysis_run.id,
                    plugin_name=plugin_name,
                    configuration={},
                )
                self.plugin_run_repository.create(plugin_create)

        except Exception as exc:
            self.state_label.setText(f"Could not create analysis run: {exc}")
            return

        if self.analysis_orchestrator is not None:
            # Disable UI controls during background execution
            self._set_controls_enabled(False)
            self.current_running_analysis_id = analysis_run.id
            self.state_label.setText(
                f"Running analysis {str(analysis_run.id)[:8]} ({len(selected_plugins)} plugins)... Please wait."
            )
            self.load_analysis_history(self.selected_evidence)
            self.select_analysis_run(analysis_run.id)

            if not self.status_poll_timer.isActive():
                self.status_poll_timer.start()

            # Create and launch background worker thread
            self.analysis_worker = AnalysisWorker(
                self.analysis_orchestrator, analysis_run.id, self
            )
            self.analysis_worker.finished.connect(self._on_analysis_finished)
            self.analysis_worker.failed.connect(self._on_analysis_failed)
            self.analysis_worker.start()
        else:
            # Staging-only fallback mode
            self.state_label.setText(
                f"Analysis run {str(analysis_run.id)[:8]} staged with {len(selected_plugins)} plugin(s) (Pending execution)."
            )
            self.load_analysis_history(self.selected_evidence)
            self.select_analysis_run(analysis_run.id)

    def _poll_running_analysis_status(self) -> None:
        """Periodically refresh plugin runs and analysis history while worker is running."""
        if self.current_running_analysis_id is not None:
            self.load_plugin_runs_for_analysis(self.current_running_analysis_id)
            if self.selected_evidence is not None:
                runs = self.analysis_run_repository.list_by_evidence(
                    self.selected_evidence.id
                )
                self.populate_runs_table(runs)
                self.select_analysis_run(self.current_running_analysis_id)

    def _stop_status_poll_timer(self) -> None:
        """Stop status polling timer if active."""
        if self.status_poll_timer.isActive():
            self.status_poll_timer.stop()
        self.current_running_analysis_id = None

    def _on_analysis_finished(self, analysis_run: AnalysisRun) -> None:
        """Handle successful AnalysisWorker completion on the GUI thread."""
        self._stop_status_poll_timer()
        self._set_controls_enabled(True)
        if self.selected_evidence is not None:
            self.load_analysis_history(self.selected_evidence)
            self.select_analysis_run(analysis_run.id)

        status_str = analysis_run.status.value.upper()
        self.state_label.setText(
            f"Analysis run {str(analysis_run.id)[:8]} finished with status: {status_str}."
        )

        if self.analysis_worker is not None:
            self.analysis_worker.deleteLater()
            self.analysis_worker = None

    def _on_analysis_failed(self, error_message: str) -> None:
        """Handle unexpected AnalysisWorker failure on the GUI thread."""
        self._stop_status_poll_timer()
        self._set_controls_enabled(True)
        if self.selected_evidence is not None:
            self.load_analysis_history(self.selected_evidence)

        self.state_label.setText(f"Analysis execution error: {error_message}")

        if self.analysis_worker is not None:
            self.analysis_worker.deleteLater()
            self.analysis_worker = None

    def _set_controls_enabled(self, enabled: bool) -> None:
        """Enable or disable interactive UI controls during analysis execution."""
        self.run_button.setEnabled(enabled)
        self.select_all_btn.setEnabled(enabled)
        self.deselect_all_btn.setEnabled(enabled)
        self.evidence_combo.setEnabled(enabled)
        if not enabled:
            self.view_output_btn.setEnabled(False)
        else:
            self.on_plugin_run_selected()

    def load_analysis_history(self, evidence: Evidence) -> None:
        """Fetch and display past analysis runs for the selected evidence."""
        self.runs_table.setRowCount(0)
        self.plugin_runs_table.setRowCount(0)
        self.view_output_btn.setEnabled(False)

        try:
            runs = self.analysis_run_repository.list_by_evidence(evidence.id)
        except Exception as exc:
            self.state_label.setText(f"Unable to load analysis history: {exc}")
            return

        self.populate_runs_table(runs)

    def populate_runs_table(self, runs: list[AnalysisRun]) -> None:
        self.runs_table.setSortingEnabled(False)
        self.runs_table.setRowCount(len(runs))

        if not runs:
            self.state_label.setText("No analysis runs recorded for this evidence file yet.")
            return

        for row, run in enumerate(runs):
            created_str = run.created_at.astimezone().strftime("%Y-%m-%d %H:%M")
            status_str = run.status.value.upper()
            error_str = run.error_message if run.error_message else "None"

            values = [
                created_str,
                status_str,
                run.host_os.value.capitalize(),
                run.volatility_version,
                error_str,
            ]

            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, run)
                self.runs_table.setItem(row, col, item)

        self.runs_table.setSortingEnabled(True)

        if runs and self.runs_table.rowCount() > 0:
            self.runs_table.selectRow(0)

    def on_analysis_run_selected(self) -> None:
        """Update plugin execution status table when an AnalysisRun row is selected."""
        row = self.runs_table.currentRow()
        if row < 0:
            self.plugin_runs_table.setRowCount(0)
            self.view_output_btn.setEnabled(False)
            return

        item = self.runs_table.item(row, 0)
        if item is None:
            self.plugin_runs_table.setRowCount(0)
            self.view_output_btn.setEnabled(False)
            return

        run = item.data(Qt.ItemDataRole.UserRole)
        if not isinstance(run, AnalysisRun):
            self.plugin_runs_table.setRowCount(0)
            self.view_output_btn.setEnabled(False)
            return

        self.load_plugin_runs_for_analysis(run.id)

    def load_plugin_runs_for_analysis(self, analysis_run_id: UUID) -> None:
        """Fetch and display individual plugin run statuses."""
        try:
            plugin_runs = self.plugin_run_repository.list_by_analysis_run(
                analysis_run_id
            )
        except Exception as exc:
            self.state_label.setText(f"Unable to load plugin run statuses: {exc}")
            self.plugin_runs_table.setRowCount(0)
            self.view_output_btn.setEnabled(False)
            return

        self.plugin_runs_table.setRowCount(len(plugin_runs))

        completed_cnt = sum(1 for pr in plugin_runs if pr.status.value == "completed")
        failed_cnt = sum(1 for pr in plugin_runs if pr.status.value == "failed" or pr.error_message)
        total_cnt = len(plugin_runs)

        if total_cnt > 0 and self.current_running_analysis_id is None:
            status_msg = f"Plugin Execution Summary: {completed_cnt}/{total_cnt} Completed"
            if failed_cnt > 0:
                status_msg += f" ({failed_cnt} Failed)"
            self.state_label.setText(status_msg)

        for row, prun in enumerate(plugin_runs):
            started_str = (
                prun.started_at.astimezone().strftime("%H:%M:%S")
                if prun.started_at is not None
                else "N/A"
            )
            completed_or_err = (
                prun.error_message
                if prun.error_message
                else (
                    prun.completed_at.astimezone().strftime("%H:%M:%S")
                    if prun.completed_at is not None
                    else "N/A"
                )
            )

            is_failed = prun.status.value == "failed" or prun.error_message is not None
            status_text = "FAILED" if is_failed else prun.status.value.upper()

            values = [
                prun.plugin_name,
                status_text,
                started_str,
                completed_or_err,
            ]

            for col, text in enumerate(values):
                item = QTableWidgetItem(text)
                if is_failed:
                    item.setForeground(QColor("#EF4444"))
                if col == 0:
                    item.setData(Qt.ItemDataRole.UserRole, prun)
                self.plugin_runs_table.setItem(row, col, item)

        if plugin_runs and self.plugin_runs_table.rowCount() > 0:
            self.plugin_runs_table.selectRow(0)
        else:
            self.on_plugin_run_selected()

    def on_plugin_run_selected(self) -> None:
        """Update View Output button state based on selected plugin run."""
        prun = self.get_selected_plugin_run()
        if prun is not None and prun.raw_output_path is not None:
            self.view_output_btn.setEnabled(True)
        else:
            self.view_output_btn.setEnabled(False)

    def get_selected_plugin_run(self) -> PluginRun | None:
        """Return the currently selected PluginRun from plugin_runs_table, if any."""
        row = self.plugin_runs_table.currentRow()
        if row < 0:
            return None
        item = self.plugin_runs_table.item(row, 0)
        if item is None:
            return None
        data = item.data(Qt.ItemDataRole.UserRole)
        return data if isinstance(data, PluginRun) else None

    def open_selected_plugin_output(self) -> None:
        """Open the generated output JSON file using the OS default application."""
        prun = self.get_selected_plugin_run()
        if prun is None:
            self.state_label.setText("No plugin run selected.")
            return

        if prun.raw_output_path is None:
            self.state_label.setText(
                f"No output file recorded for plugin run '{prun.plugin_name}'."
            )
            return

        out_path = Path(prun.raw_output_path)
        if not out_path.exists() or not out_path.is_file():
            self.state_label.setText(
                f"Output file for '{prun.plugin_name}' not found: {out_path}"
            )
            return

        url = QUrl.fromLocalFile(str(out_path.resolve()))
        success = QDesktopServices.openUrl(url)
        if success:
            self.state_label.setText(
                f"Opened output file for '{prun.plugin_name}': {out_path.name}"
            )
        else:
            self.state_label.setText(
                f"Could not open output file with system viewer: {out_path}"
            )

    def select_analysis_run(self, analysis_run_id: UUID) -> None:
        """Select row matching analysis_run_id in runs_table."""
        for row in range(self.runs_table.rowCount()):
            item = self.runs_table.item(row, 0)
            if item is None:
                continue
            run = item.data(Qt.ItemDataRole.UserRole)
            if isinstance(run, AnalysisRun) and run.id == analysis_run_id:
                self.runs_table.selectRow(row)
                return

    def clear_all_views(self) -> None:
        """Reset all tables, lists, and summary cards."""
        self.evidence_info_card.setText("No evidence selected")
        self.plugins_status_label.setText(
            "Select an evidence item to configure plugins."
        )
        self.plugins_list.clear()
        self.runs_table.setRowCount(0)
        self.plugin_runs_table.setRowCount(0)
        self.run_button.setEnabled(False)
        self.select_all_btn.setEnabled(False)
        self.deselect_all_btn.setEnabled(False)
        self.view_output_btn.setEnabled(False)
