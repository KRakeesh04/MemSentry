"""Report Builder View for MemSentry.

Generates and previews comprehensive forensic investigation reports in PDF, DOCX, and HTML formats
including evidence hash integrity, process triage anomalies, MITRE ATT&CK mapping, and timeline logs.
"""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPushButton,
    QScrollArea,
    QSplitter,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from memsentry.gui.theme import create_badge_label


class ReportBuilderView(QWidget):
    """Report Builder view for compiling DFIR findings, cryptographic hashes, and timeline logs."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setObjectName("ReportBuilderView")
        self._init_ui()

    def _init_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(16, 12, 16, 12)
        main_layout.setSpacing(10)

        # 1. Top Sub-Header Bar
        header_box = QHBoxLayout()
        header_box.setSpacing(12)

        title_layout = QVBoxLayout()
        title_layout.setSpacing(2)

        subtitle_hdr = QLabel("REPORT BUILDER")
        subtitle_hdr.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B; letter-spacing: 0.5px;")
        title_layout.addWidget(subtitle_hdr)

        main_title_lbl = QLabel("Build Forensic Investigation Report")
        main_title_lbl.setStyleSheet("font-size: 20px; font-weight: 800; color: #F8FAFC;")
        title_layout.addWidget(main_title_lbl)

        desc_lbl = QLabel("Configure report sections, select findings, and generate a professional forensic report document.")
        desc_lbl.setStyleSheet("font-size: 12px; color: #94A3B8;")
        title_layout.addWidget(desc_lbl)

        header_box.addLayout(title_layout)
        header_box.addStretch()
        main_layout.addLayout(header_box)

        # 2. Main Center Splitter (Left: Config Panel, Right: Report Preview & Export)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setStyleSheet("QSplitter::handle { background: #1E293B; width: 1px; }")

        # Left Column: Configuration Scroll Panel
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(0)

        scroll_config = QScrollArea()
        scroll_config.setWidgetResizable(True)
        scroll_config.setStyleSheet("QScrollArea { background: transparent; border: none; }")

        config_container = QWidget()
        config_box = QVBoxLayout(config_container)
        config_box.setContentsMargins(0, 0, 8, 0)
        config_box.setSpacing(14)

        # Section 1: Report Information
        info_hdr = QLabel("Report Information")
        info_hdr.setStyleSheet("font-size: 13px; font-weight: 700; color: #CBD5E1;")
        config_box.addWidget(info_hdr)

        info_card = QFrame()
        info_card.setStyleSheet("background: #0D1322; border: 1px solid #1E293B; border-radius: 6px;")
        info_layout = QVBoxLayout(info_card)
        info_layout.setContentsMargins(14, 14, 14, 14)
        info_layout.setSpacing(12)

        # Title Field
        info_layout.addWidget(self._create_field_label("Report Title"))
        self.title_input = QLineEdit("Forensic Analysis Report — CORP-2024-0187")
        self.title_input.setStyleSheet(self._input_style())
        self.title_input.textChanged.connect(self._update_preview_title)
        info_layout.addWidget(self.title_input)

        # Row 1: Case ID & Analyst
        row1 = QHBoxLayout()
        row1.setSpacing(12)

        col1_layout = QVBoxLayout()
        col1_layout.addWidget(self._create_field_label("Case ID"))
        self.case_id_input = QLineEdit("CORP-2024-0187")
        self.case_id_input.setReadOnly(True)
        self.case_id_input.setStyleSheet(self._input_disabled_style())
        col1_layout.addWidget(self.case_id_input)
        row1.addLayout(col1_layout, stretch=1)

        col2_layout = QVBoxLayout()
        col2_layout.addWidget(self._create_field_label("Analyst"))
        self.investigator_input = QLineEdit("J. Mercer")
        self.investigator_input.setStyleSheet(self._input_style())
        self.investigator_input.textChanged.connect(self._update_preview_analyst)
        col2_layout.addWidget(self.investigator_input)
        row1.addLayout(col2_layout, stretch=1)

        info_layout.addLayout(row1)

        # Row 2: Evidence & Date
        row2 = QHBoxLayout()
        row2.setSpacing(12)

        col3_layout = QVBoxLayout()
        col3_layout.addWidget(self._create_field_label("Evidence"))
        self.evidence_input = QLineEdit("WINSERVER2019-DC01.raw")
        self.evidence_input.setReadOnly(True)
        self.evidence_input.setStyleSheet(self._input_disabled_style())
        col3_layout.addWidget(self.evidence_input)
        row2.addLayout(col3_layout, stretch=1)

        col4_layout = QVBoxLayout()
        col4_layout.addWidget(self._create_field_label("Date"))
        self.date_input = QLineEdit("2024-11-15")
        self.date_input.setStyleSheet(self._input_style())
        col4_layout.addWidget(self.date_input)
        row2.addLayout(col4_layout, stretch=1)

        info_layout.addLayout(row2)

        # Classification Field
        info_layout.addWidget(self._create_field_label("Classification"))
        self.classification_combo = QComboBox()
        self.classification_combo.addItems(["RESTRICTED", "CONFIDENTIAL", "TLP:AMBER", "INTERNAL ONLY", "UNCLASSIFIED"])
        self.classification_combo.setStyleSheet(
            "background: #080C14; border: 1px solid #1E293B; color: #F8FAFC; "
            "padding: 6px 10px; border-radius: 4px; font-size: 12px; font-weight: 600;"
        )
        self.classification_combo.currentTextChanged.connect(self._update_preview_classification)
        info_layout.addWidget(self.classification_combo)

        # Legacy Compatibility Combo
        self.format_combo = QComboBox()
        self.format_combo.addItems(["PDF", "DOCX", "HTML"])
        self.format_combo.hide()

        config_box.addWidget(info_card)

        # Section 2: Report Sections (10/13)
        sections_hdr = QLabel("Report Sections (10/13)")
        sections_hdr.setStyleSheet("font-size: 13px; font-weight: 700; color: #CBD5E1; margin-top: 6px;")
        config_box.addWidget(sections_hdr)

        sections_list = [
            ("Cover Page & Executive Summary", "Case details, classification, and high-level summary", True, True, "chk_exec"),
            ("Evidence Integrity", "Memory dump metadata, SHA-256 verification, acquisition chain of custody", True, True, "chk_hash"),
            ("System Environment", "Target OS, architecture, kernel profile, running processes overview", True, False, "chk_env"),
            ("Analysis Methodology", "Volatility plugins executed, framework configuration, triage rules", True, False, "chk_vol"),
            ("Key Findings", "Correlated threat findings, risk scoring, severity rankings", True, False, "chk_proc"),
            ("Process Analysis", "Process tree hierarchy, DLL modules, unbacked code injection", True, False, "chk_pa"),
            ("Network Activity", "Active TCP/UDP sockets, remote C2 endpoints, listening ports", True, False, "chk_net"),
            ("Event Timeline", "Chronological sequence of process and network events", True, False, "chk_timeline"),
            ("Indicators of Compromise", "IOC list (IPs, file names, memory offsets, hashes)", True, False, "chk_ioc"),
            ("MITRE ATT&CK Mapping", "ATT&CK matrix techniques and tactic correlations", True, False, "chk_mitre"),
        ]

        for s_title, s_desc, is_chk, is_req, attr_name in sections_list:
            card = QFrame()
            card.setStyleSheet("background: #0D1322; border: 1px solid #1E293B; border-radius: 6px;")
            card_layout = QHBoxLayout(card)
            card_layout.setContentsMargins(14, 10, 14, 10)
            card_layout.setSpacing(12)

            chk = QCheckBox()
            chk.setChecked(is_chk)
            chk.setStyleSheet("QCheckBox::indicator { width: 18px; height: 18px; }")
            setattr(self, attr_name, chk)
            card_layout.addWidget(chk)

            text_box = QVBoxLayout()
            text_box.setSpacing(2)

            header_row = QHBoxLayout()
            header_row.setSpacing(8)

            lbl = QLabel(s_title)
            lbl.setStyleSheet("font-size: 13px; font-weight: 700; color: #F8FAFC;")
            header_row.addWidget(lbl)

            if is_req:
                req_badge = QLabel("required")
                req_badge.setStyleSheet(
                    "background: #1E293B; color: #94A3B8; font-size: 10px; font-weight: 600; "
                    "padding: 1px 6px; border-radius: 3px;"
                )
                header_row.addWidget(req_badge)

            header_row.addStretch()
            text_box.addLayout(header_row)

            sub_lbl = QLabel(s_desc)
            sub_lbl.setStyleSheet("font-size: 11px; color: #64748B;")
            text_box.addWidget(sub_lbl)

            card_layout.addLayout(text_box, stretch=1)
            config_box.addWidget(card)

        config_box.addStretch()
        scroll_config.setWidget(config_container)
        left_layout.addWidget(scroll_config)
        splitter.addWidget(left_widget)

        # Right Column: Report Preview & Export Panel
        right_panel = QFrame()
        right_panel.setFixedWidth(340)
        right_panel.setStyleSheet("background: #0D1322; border: 1px solid #1E293B; border-radius: 6px;")
        right_layout = QVBoxLayout(right_panel)
        right_layout.setContentsMargins(16, 16, 16, 16)
        right_layout.setSpacing(14)

        prev_hdr = QLabel("REPORT PREVIEW")
        prev_hdr.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B; letter-spacing: 0.5px;")
        right_layout.addWidget(prev_hdr)

        # Document Preview Card Container
        doc_card = QFrame()
        doc_card.setStyleSheet("background: #080C14; border: 1px solid #1E293B; border-radius: 6px;")
        doc_layout = QVBoxLayout(doc_card)
        doc_layout.setContentsMargins(14, 14, 14, 14)
        doc_layout.setSpacing(10)

        # Preview Classification Badge
        self.prev_class_badge = create_badge_label("RESTRICTED", "critical")
        self.prev_class_badge.setStyleSheet(
            "background: #450A0A; color: #EF4444; font-size: 10px; font-weight: 800; border-radius: 3px; padding: 2px 6px;"
        )
        doc_layout.addWidget(self.prev_class_badge)

        self.prev_title_lbl = QLabel("Forensic Analysis Report — CORP-2024-0187")
        self.prev_title_lbl.setStyleSheet("font-size: 14px; font-weight: 800; color: #F8FAFC;")
        self.prev_title_lbl.setWordWrap(True)
        doc_layout.addWidget(self.prev_title_lbl)

        self.prev_meta_lbl = QLabel("CORP-2024-0187  ·  J. Mercer")
        self.prev_meta_lbl.setStyleSheet("font-family: monospace; font-size: 11px; color: #64748B;")
        doc_layout.addWidget(self.prev_meta_lbl)

        # Table of Contents Section
        toc_hdr = QLabel("TABLE OF CONTENTS")
        toc_hdr.setStyleSheet("font-size: 10px; font-weight: 700; color: #64748B; margin-top: 4px;")
        doc_layout.addWidget(toc_hdr)

        toc_items = [
            "1. Cover Page & Executive Summary",
            "2. Evidence Integrity",
            "3. System Environment",
            "4. Analysis Methodology",
            "5. Key Findings",
            "6. Process Analysis",
            "7. Network Activity",
            "8. Event Timeline",
            "9. Indicators of Compromise",
            "10. MITRE ATT&CK Mapping",
        ]
        for item_text in toc_items:
            t_item = QLabel(item_text)
            t_item.setStyleSheet("font-size: 11px; color: #94A3B8;")
            doc_layout.addWidget(t_item)

        # Findings Included Section
        findings_hdr = QLabel("FINDINGS INCLUDED")
        findings_hdr.setStyleSheet("font-size: 10px; font-weight: 700; color: #64748B; margin-top: 6px;")
        doc_layout.addWidget(findings_hdr)

        f_items = [
            "Malicious Office Macro — PowerShell Ex...",
            "C2 Beacon — TOR Exit Node (Cobalt Stri...",
            "Process Injection — Hollowed svchost.exe",
            "Reverse Shell — Meterpreter on Port 4444",
        ]
        for f_text in f_items:
            f_row = QHBoxLayout()
            f_row.setSpacing(6)
            c_tag = QLabel("C")
            c_tag.setStyleSheet(
                "background: #450A0A; color: #EF4444; font-size: 9px; font-weight: 800; "
                "padding: 1px 4px; border-radius: 2px;"
            )
            f_row.addWidget(c_tag)

            f_lbl = QLabel(f_text)
            f_lbl.setStyleSheet("font-size: 10.5px; color: #CBD5E1;")
            f_row.addWidget(f_lbl)
            f_row.addStretch()
            doc_layout.addLayout(f_row)

        right_layout.addWidget(doc_card)

        # Hidden preview text for legacy compatibility
        self.preview_text = QTextEdit()
        self.preview_text.hide()
        self._update_mock_report_content()

        # Export Format Segment Selector
        exp_hdr = QLabel("Export Format")
        exp_hdr.setStyleSheet("font-size: 11px; font-weight: 700; color: #64748B;")
        right_layout.addWidget(exp_hdr)

        format_bar = QHBoxLayout()
        format_bar.setSpacing(4)

        self.btn_pdf = QPushButton("PDF")
        self.btn_pdf.setStyleSheet(
            "background: #1D4ED8; border: 1px solid #2563EB; color: #F8FAFC; "
            "font-size: 12px; font-weight: 700; padding: 6px; border-radius: 4px;"
        )
        self.btn_pdf.clicked.connect(lambda: self._select_format("PDF"))
        format_bar.addWidget(self.btn_pdf, stretch=1)

        self.btn_docx = QPushButton("DOCX")
        self.btn_docx.setStyleSheet(
            "background: #1E293B; border: 1px solid #334155; color: #94A3B8; "
            "font-size: 12px; font-weight: 600; padding: 6px; border-radius: 4px;"
        )
        self.btn_docx.clicked.connect(lambda: self._select_format("DOCX"))
        format_bar.addWidget(self.btn_docx, stretch=1)

        self.btn_html = QPushButton("HTML")
        self.btn_html.setStyleSheet(
            "background: #1E293B; border: 1px solid #334155; color: #94A3B8; "
            "font-size: 12px; font-weight: 600; padding: 6px; border-radius: 4px;"
        )
        self.btn_html.clicked.connect(lambda: self._select_format("HTML"))
        format_bar.addWidget(self.btn_html, stretch=1)

        right_layout.addLayout(format_bar)
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

        # Generate Report Button
        generate_btn = QPushButton("Generate Report")
        generate_btn.setObjectName("PrimaryButton")
        generate_btn.setStyleSheet(
            "background: #1D4ED8; border: 1px solid #2563EB; color: #F8FAFC; "
            "font-size: 15px; font-weight: 800; padding: 10px; border-radius: 6px;"
        )
        generate_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        generate_btn.clicked.connect(self._on_generate_clicked)
        right_layout.addWidget(generate_btn)

        splitter.addWidget(right_panel)
        splitter.setSizes([650, 350])

        main_layout.addWidget(splitter, stretch=1)

    def _create_field_label(self, text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet("font-size: 11px; font-weight: 600; color: #64748B;")
        return lbl

    def _input_style(self) -> str:
        return (
            "background: #080C14; border: 1px solid #1E293B; color: #F8FAFC; "
            "padding: 6px 10px; border-radius: 4px; font-size: 12px;"
        )

    def _input_disabled_style(self) -> str:
        return (
            "background: #0B0F19; border: 1px solid #1E293B; color: #64748B; "
            "padding: 6px 10px; border-radius: 4px; font-size: 12px; font-family: monospace;"
        )

    def _select_format(self, fmt: str) -> None:
        buttons = [("PDF", self.btn_pdf), ("DOCX", self.btn_docx), ("HTML", self.btn_html)]
        for label, btn in buttons:
            if label == fmt:
                btn.setStyleSheet(
                    "background: #1D4ED8; border: 1px solid #2563EB; color: #F8FAFC; "
                    "font-size: 12px; font-weight: 700; padding: 6px; border-radius: 4px;"
                )
            else:
                btn.setStyleSheet(
                    "background: #1E293B; border: 1px solid #334155; color: #94A3B8; "
                    "font-size: 12px; font-weight: 600; padding: 6px; border-radius: 4px;"
                )
        idx = self.format_combo.findText(fmt)
        if idx >= 0:
            self.format_combo.setCurrentIndex(idx)

    def _update_preview_title(self, text: str) -> None:
        self.prev_title_lbl.setText(text if text else "Forensic Analysis Report")

    def _update_preview_analyst(self, text: str) -> None:
        cid = self.case_id_input.text()
        self.prev_meta_lbl.setText(f"{cid}  ·  {text}")

    def _update_preview_classification(self, text: str) -> None:
        self.prev_class_badge.setText(text)

    def _update_mock_report_content(self) -> None:
        sample_report = """================================================================================
                    MEMSENTRY DIGITAL FORENSIC EXAMINATION REPORT
================================================================================
Case Title     : Memory Injection Analysis - Workstation 105
Case Reference : CASE-2026-0042
Target Evidence: win10_memory_dump.raw (2,147,483,648 bytes)
Investigator   : Lead Forensic Analyst
Generated At   : 2026-09-08 21:39:53 UTC

1. CRYPTOGRAPHIC HASH CHAIN INTEGRITY AUDIT
--------------------------------------------------------------------------------
Initial SHA-256 (Pre-Analysis)  : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Re-calculated SHA-256           : e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
Status                          : VERIFIED INTEGRITY MATCH (NO MUTATION DETECTED)

2. EXECUTIVE SUMMARY & ANOMALY HIGHLIGHTS
--------------------------------------------------------------------------------
MemSentry automated memory triage detected 1 CRITICAL threat indicator and 2 HIGH risk anomalies
within the provided Windows 10 x64 memory artifact.

Primary Finding: Process 'powershell.exe' (PID 5828, PPID 4120) contains unbacked execute-read-write
(PAGE_EXECUTE_READWRITE) memory regions with shellcode characteristics.

3. VOLATILITY 3 PLUGIN EXECUTION MATRIX
--------------------------------------------------------------------------------
[✓] windows.info      - Completed (00:00:04) - OS: Windows 10.0.19041 x64
[✓] windows.pslist    - Completed (00:00:08) - Active Processes: 84
[✓] windows.pstree    - Completed (00:00:12) - Parent-Child Tree Built
[✓] windows.malfind   - Completed (00:04:15) - ANOMALY DETECTED (PID 5828)
[✓] windows.netscan   - Completed (00:01:42) - Active Connections: 14
[✓] windows.cmdline   - Completed (00:00:09) - Command line extracted

4. PROCESS TRIAGE & DETECTED ANOMALIES
--------------------------------------------------------------------------------
PID 5828 | powershell.exe | Risk Score: 98/100 | Severity: CRITICAL
  - Triggered Rule: windows.malfind
  - Header Hex     : 4d 5a 90 00 03 00 00 00 (Reflectively Loaded PE / Cobalt Strike Beacon)
  - Network C2     : 192.168.1.105:49718 -> 45.33.32.156:443 (ESTABLISHED)

PID 1024 | svchost.exe    | Risk Score: 72/100 | Severity: HIGH
  - Triggered Rule: Parent Process Spoofing / Unbacked Module

5. INVESTIGATION TIMELINE LOG
--------------------------------------------------------------------------------
2026-09-08 21:30:12 UTC - System Boot (win10_memory_dump.raw)
2026-09-08 21:34:01 UTC - Process Spawning: cmd.exe (PID 4120) by explorer.exe (PID 2840)
2026-09-08 21:34:03 UTC - Suspicious Process Execution: powershell.exe -nop -w hidden (PID 5828)
2026-09-08 21:34:05 UTC - Outbound Socket Established to 45.33.32.156:443
2026-09-08 21:38:10 UTC - Memory Dump Acquired & Registered in MemSentry

================================================================================
End of Forensic Report | MemSentry v1.0 Enterprise DFIR Suite
================================================================================
"""
        self.preview_text.setText(sample_report)

    def _on_generate_clicked(self) -> None:
        self._update_mock_report_content()
