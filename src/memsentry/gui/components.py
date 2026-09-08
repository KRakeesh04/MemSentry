"""Compact vertical sidebar and top header matching Figma visual reference."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QListWidget,
    QListWidgetItem,
    QPushButton,
    QVBoxLayout,
    QWidget,
)

from memsentry.gui.theme import (
    COLOR_BG_DARK,
    COLOR_BG_HEADER,
    COLOR_TEXT_MAIN,
    COLOR_TEXT_MUTED,
    create_badge_label,
)


class SidebarWidget(QWidget):
    """Compact vertical sidebar matching Figma icon navigation."""

    navigation_changed = Signal(int)

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedWidth(72)
        self._build_ui()

    def _build_ui(self) -> None:
        self.setStyleSheet(f"background-color: {COLOR_BG_DARK}; border-right: 1px solid #1E293B;")
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 16, 8, 16)
        layout.setSpacing(12)

        # Top Hex/Shield Logo Icon Button
        logo_btn = QPushButton("🛡️")
        logo_btn.setFixedSize(48, 48)
        logo_btn.setStyleSheet(
            "background-color: #1E3A8A; color: #60A5FA; border: 1px solid #2563EB; border-radius: 12px; font-size: 22px;"
        )
        logo_btn.setToolTip("MemSentry DFIR Suite")

        logo_layout = QHBoxLayout()
        logo_layout.addStretch()
        logo_layout.addWidget(logo_btn)
        logo_layout.addStretch()
        layout.addLayout(logo_layout)

        # Icon-oriented QListWidget
        self.nav_list = QListWidget()
        self.nav_list.setStyleSheet(
            f"""
            QListWidget {{
                background-color: transparent;
                border: none;
                outline: 0;
            }}
            QListWidget::item {{
                height: 48px;
                margin-bottom: 6px;
                border-radius: 10px;
                color: {COLOR_TEXT_MUTED};
                font-size: 18px;
                font-weight: 700;
                border: none;
            }}
            QListWidget::item:hover {{
                background-color: #1E293B;
                color: {COLOR_TEXT_MAIN};
            }}
            QListWidget::item:selected {{
                background-color: #2563EB;
                color: #FFFFFF;
            }}
            """
        )

        nav_items_data = [
            ("⊞", "Command Center"),
            ("⤓", "Cases"),
            ("🔍", "Evidence Explorer"),
            ("⚡", "Analysis Center"),
            ("⚠️ 5", "Findings Dashboard (5 Alerts)"),
            ("🕒", "Investigation Timeline"),
            ("☊", "Relationship Graph"),
            ("📄", "Report Builder"),
        ]

        for icon_symbol, tooltip_text in nav_items_data:
            item = QListWidgetItem(icon_symbol)
            item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
            item.setToolTip(tooltip_text)
            self.nav_list.addItem(item)

        self.nav_list.currentRowChanged.connect(self.navigation_changed.emit)
        layout.addWidget(self.nav_list, stretch=1)

        # Bottom Controls (Theme toggle & Help ?)
        theme_btn = QPushButton("⚙️")
        theme_btn.setFixedSize(40, 40)
        theme_btn.setStyleSheet("background: transparent; border: none; font-size: 18px; color: #64748B;")
        theme_btn.setToolTip("Settings")

        help_btn = QPushButton("?")
        help_btn.setFixedSize(36, 36)
        help_btn.setStyleSheet(
            "background-color: #1E293B; color: #94A3B8; border: 1px solid #334155; border-radius: 18px; font-weight: 800; font-size: 14px;"
        )
        help_btn.setToolTip("Documentation & Help")

        bottom_box = QVBoxLayout()
        bottom_box.setSpacing(8)

        for b in [theme_btn, help_btn]:
            bx = QHBoxLayout()
            bx.addStretch()
            bx.addWidget(b)
            bx.addStretch()
            bottom_box.addLayout(bx)

        layout.addLayout(bottom_box)

        # Default selection
        self.nav_list.setCurrentRow(0)

    def set_active_case_display(self, case_name: str | None, status_str: str = "ACTIVE") -> None:
        """Update active investigation context tooltip indicator."""
        if case_name:
            self.nav_list.setToolTip(f"Active Case: {case_name} [{status_str}]")
        else:
            self.nav_list.setToolTip("No active case opened")


class TopHeader(QWidget):
    """Top bar matching Figma header with MemSentry logo, breadcrumbs, search, and analyst context."""

    create_case_requested = Signal()
    add_evidence_requested = Signal()

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setFixedHeight(56)
        self._build_ui()

    def _build_ui(self) -> None:
        self.setStyleSheet(
            f"background-color: {COLOR_BG_HEADER}; border-bottom: 1px solid #1E293B;"
        )
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 8, 20, 8)
        layout.setSpacing(16)

        # MemSentry Branding Logo Text
        brand_label = QLabel("MEMSENTRY")
        brand_label.setStyleSheet("color: #F9FAFB; font-size: 17px; font-weight: 900; letter-spacing: 1.5px;")

        divider = QLabel("│")
        divider.setStyleSheet("color: #334155; font-size: 14px;")

        # Investigation / Case Context Breadcrumbs
        self.breadcrumb_label = QLabel("CORP-2024-0187  ·  Suspected APT Intrusion — Domain Controller  ·  WINSERVER2019-DC01.raw")
        self.breadcrumb_label.setStyleSheet("color: #94A3B8; font-size: 12px; font-weight: 500;")

        # Global Search Input matching Figma `Q Quick search ⌘K`
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("🔍  Quick search  ⌘K")
        self.search_input.setFixedWidth(240)
        self.search_input.setStyleSheet(
            "background-color: #0F172A; border: 1px solid #1E293B; border-radius: 6px; padding: 6px 12px; color: #94A3B8; font-size: 12px;"
        )

        # Status Pill: Red active investigation dot
        self.status_pill = create_badge_label("● Active Investigation", "critical")
        self.status_pill.setStyleSheet(
            "background-color: rgba(239, 68, 68, 0.15); color: #EF4444; border: 1px solid #EF4444; border-radius: 14px; padding: 4px 12px; font-size: 11px; font-weight: 700;"
        )

        # Analyst Avatar Pill
        self.avatar_pill = QLabel("JM  J. Mercer")
        self.avatar_pill.setStyleSheet(
            "background-color: #1E293B; color: #F1F5F9; border: 1px solid #334155; border-radius: 14px; padding: 4px 12px; font-size: 11px; font-weight: 700;"
        )

        layout.addWidget(brand_label)
        layout.addWidget(divider)
        layout.addWidget(self.breadcrumb_label)
        layout.addStretch()
        layout.addWidget(self.search_input)
        layout.addWidget(self.status_pill)
        layout.addWidget(self.avatar_pill)

    def set_title_and_subtitle(self, title: str, subtitle: str) -> None:
        if "CORP-2024-0187" in subtitle or "Active" in subtitle:
            self.breadcrumb_label.setText(subtitle)
        else:
            self.breadcrumb_label.setText(f"{title}  ·  {subtitle}")
