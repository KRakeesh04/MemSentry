"""Help and documentation page for MemSentry workflows and diagnostics."""

from __future__ import annotations

import importlib.util
import platform
import sys

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)
from volatility3.framework import constants

from memsentry.version import __version__


class HelpPage(QScrollArea):
    """User documentation, workflow guide, and system diagnostics page."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.Shape.NoFrame)

        content = QWidget()
        layout = QVBoxLayout(content)
        layout.setContentsMargins(32, 32, 32, 32)
        layout.setSpacing(24)

        # Header
        heading = QHBoxLayout()
        title = QLabel("Help & Documentation")
        title.setObjectName("pageTitle")
        heading.addWidget(title)
        heading.addStretch()
        layout.addLayout(heading)

        subtitle = QLabel(
            "Quick reference guide for memory evidence acquisition, Volatility 3 analysis, and forensic investigation workflows."
        )
        subtitle.setObjectName("muted")
        subtitle.setWordWrap(True)
        layout.addWidget(subtitle)

        # Section 1: Workflow Guide (Grid of Cards)
        guide_title = QLabel("Investigation Workflow")
        guide_title.setObjectName("sectionTitle")
        layout.addWidget(guide_title)

        grid = QGridLayout()
        grid.setSpacing(16)

        steps = [
            (
                "1 · Case Setup & Intake",
                "Create an investigation case in a workspace folder. Import existing memory dumps (.dmp, .raw, .vmem) or acquire live system RAM using elevated tools.",
            ),
            (
                "2 · Baseline Verification",
                "MemSentry automatically computes SHA-256 hashes before and after analysis to ensure memory images remain read-only and un-tampered.",
            ),
            (
                "3 · Volatility 3 Analysis",
                "Run automated Volatility 3 plugins (pslist, pstree, cmdline, netscan, malfind) and YARA rules to detect code injection and process anomalies.",
            ),
            (
                "4 · Correlation & Findings",
                "Review automated findings prioritized by severity (Critical, High, Medium, Low) and explore process contexts and network artifacts.",
            ),
        ]

        for index, (header, text) in enumerate(steps):
            card = QFrame()
            card.setObjectName("card")
            card_layout = QVBoxLayout(card)
            card_layout.setContentsMargins(16, 16, 16, 16)
            card_layout.setSpacing(8)

            step_header = QLabel(header)
            step_header.setObjectName("sectionTitle")
            step_text = QLabel(text)
            step_text.setWordWrap(True)
            step_text.setObjectName("muted")

            card_layout.addWidget(step_header)
            card_layout.addWidget(step_text)
            grid.addWidget(card, index // 2, index % 2)

        layout.addLayout(grid)

        # Section 2: System & Diagnostic Info
        diag_title = QLabel("System & Diagnostic Information")
        diag_title.setObjectName("sectionTitle")
        layout.addWidget(diag_title)

        diag_card = QFrame()
        diag_card.setObjectName("card")
        diag_layout = QVBoxLayout(diag_card)
        diag_layout.setContentsMargins(20, 16, 20, 16)
        diag_layout.setSpacing(10)

        yara_spec = importlib.util.find_spec("yara")
        yara_status = "Available (yara-python)" if yara_spec else "Not installed"

        info_items = [
            ("MemSentry Core Version", __version__),
            ("Volatility 3 Version", constants.PACKAGE_VERSION),
            ("YARA Scanner Status", yara_status),
            ("Python Runtime", f"{sys.version.split()[0]} ({platform.system()} {platform.machine()})"),
            ("Supported Formats", ".dmp, .raw, .vmem, .mem, .lime, .bin"),
        ]

        for label_text, value_text in info_items:
            row = QHBoxLayout()
            lbl = QLabel(label_text)
            val = QLabel(value_text)
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            val.setObjectName("muted")
            row.addWidget(lbl)
            row.addStretch()
            row.addWidget(val)
            diag_layout.addLayout(row)

        layout.addWidget(diag_card)
        layout.addStretch()
        self.setWidget(content)


def create_page() -> HelpPage:
    return HelpPage()
