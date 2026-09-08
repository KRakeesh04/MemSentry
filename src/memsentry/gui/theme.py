"""Design system, color tokens, and QSS styles for the modern MemSentry DFIR suite."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

# Color Palette Tokens
COLOR_BG_DARK = "#0B0F19"       # Deep dark window background
COLOR_BG_PANEL = "#111827"      # Card / panel background
COLOR_BG_HEADER = "#1F2937"     # Top header background
COLOR_BG_HOVER = "#374151"      # Hover state background
COLOR_BORDER = "#1F2937"        # Subtle border color
COLOR_ACCENT = "#3B82F6"        # Primary blue accent
COLOR_ACCENT_HOVER = "#2563EB"  # Primary blue hover
COLOR_CYAN = "#06B6D4"          # Info / secondary accent

# Severity Colors
COLOR_CRITICAL = "#EF4444"      # Critical red
COLOR_HIGH = "#F97316"          # High orange
COLOR_MEDIUM = "#FBBF24"        # Medium amber/yellow
COLOR_LOW = "#3B82F6"           # Low blue
COLOR_SUCCESS = "#10B981"       # Success green

# Text Colors
COLOR_TEXT_MAIN = "#F9FAFB"     # Main white text
COLOR_TEXT_MUTED = "#9CA3AF"    # Muted gray text
COLOR_TEXT_DIM = "#6B7280"      # Dim gray text

MEMSENTRY_QSS = f"""
QMainWindow {{
    background-color: {COLOR_BG_DARK};
    color: {COLOR_TEXT_MAIN};
}}

QWidget {{
    font-family: 'Segoe UI', 'Inter', -apple-system, sans-serif;
    font-size: 13px;
    color: {COLOR_TEXT_MAIN};
}}

/* Scrollbars */
QScrollBar:vertical {{
    border: none;
    background: {COLOR_BG_DARK};
    width: 8px;
    margin: 0px;
}}
QScrollBar::handle:vertical {{
    background: #374151;
    min-height: 20px;
    border-radius: 4px;
}}
QScrollBar::handle:vertical:hover {{
    background: #4B5563;
}}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    border: none;
    background: {COLOR_BG_DARK};
    height: 8px;
    margin: 0px;
}}
QScrollBar::handle:horizontal {{
    background: #374151;
    min-width: 20px;
    border-radius: 4px;
}}
QScrollBar::handle:horizontal:hover {{
    background: #4B5563;
}}

/* Buttons */
QPushButton {{
    background-color: #1F2937;
    color: {COLOR_TEXT_MAIN};
    border: 1px solid #374151;
    border-radius: 6px;
    padding: 7px 16px;
    font-weight: 600;
}}
QPushButton:hover {{
    background-color: #374151;
    border-color: #4B5563;
}}
QPushButton:pressed {{
    background-color: #111827;
}}
QPushButton:disabled {{
    background-color: #111827;
    color: #4B5563;
    border-color: #1F2937;
}}

QPushButton#primaryButton {{
    background-color: {COLOR_ACCENT};
    color: #FFFFFF;
    border: none;
}}
QPushButton#primaryButton:hover {{
    background-color: {COLOR_ACCENT_HOVER};
}}

QPushButton#dangerButton {{
    background-color: {COLOR_CRITICAL};
    color: #FFFFFF;
    border: none;
}}

/* Input Controls */
QLineEdit, QComboBox, QTextEdit, QPlainTextEdit {{
    background-color: #111827;
    border: 1px solid #374151;
    border-radius: 6px;
    padding: 7px 12px;
    color: {COLOR_TEXT_MAIN};
    selection-background-color: {COLOR_ACCENT};
}}
QLineEdit:focus, QComboBox:focus, QTextEdit:focus {{
    border-color: {COLOR_ACCENT};
}}
QComboBox::drop-down {{
    border: none;
    width: 24px;
}}
QComboBox QAbstractItemView {{
    background-color: #1F2937;
    border: 1px solid #374151;
    selection-background-color: {COLOR_ACCENT};
    color: {COLOR_TEXT_MAIN};
}}

/* Table Styling */
QTableWidget, QTreeWidget, QListWidget {{
    background-color: {COLOR_BG_PANEL};
    border: 1px solid #1F2937;
    border-radius: 8px;
    gridline-color: #1F2937;
    outline: 0;
}}
QTableWidget::item, QListWidget::item {{
    padding: 8px 12px;
    border-bottom: 1px solid #1F2937;
}}
QTableWidget::item:selected, QListWidget::item:selected {{
    background-color: #1E3A8A;
    color: #FFFFFF;
}}
QHeaderView::section {{
    background-color: #1F2937;
    color: {COLOR_TEXT_MUTED};
    padding: 8px 12px;
    font-weight: 600;
    font-size: 11px;
    text-transform: uppercase;
    border: none;
    border-bottom: 2px solid #374151;
}}

/* Group Boxes & Frames */
QGroupBox {{
    font-weight: 600;
    font-size: 14px;
    border: 1px solid #1F2937;
    border-radius: 8px;
    margin-top: 12px;
    padding-top: 16px;
    background-color: {COLOR_BG_PANEL};
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    padding: 0 8px;
    color: {COLOR_ACCENT};
}}

QFrame#cardFrame {{
    background-color: {COLOR_BG_PANEL};
    border: 1px solid #1F2937;
    border-radius: 8px;
}}

/* Progress Bar */
QProgressBar {{
    border: 1px solid #374151;
    border-radius: 6px;
    text-align: center;
    background-color: #111827;
    color: {COLOR_TEXT_MAIN};
}}
QProgressBar::chunk {{
    background-color: {COLOR_ACCENT};
    border-radius: 5px;
}}

/* Tab Widget */
QTabWidget::pane {{
    border: 1px solid #1F2937;
    background-color: {COLOR_BG_PANEL};
    border-radius: 8px;
}}
QTabBar::tab {{
    background-color: #111827;
    border: 1px solid #1F2937;
    padding: 8px 16px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
    margin-right: 2px;
    color: {COLOR_TEXT_MUTED};
}}
QTabBar::tab:selected {{
    background-color: {COLOR_BG_PANEL};
    color: {COLOR_ACCENT};
    border-bottom-color: {COLOR_ACCENT};
    font-weight: 600;
}}
"""


def create_card_frame(parent: QWidget | None = None) -> QFrame:
    """Create a standardized card container frame with dark panel styling."""
    frame = QFrame(parent)
    frame.setObjectName("cardFrame")
    return frame


def create_badge_label(text: str, badge_type: str = "info") -> QLabel:
    """
    Create a styled status/severity pill badge.

    badge_type options: 'critical', 'high', 'medium', 'low', 'success', 'info', 'active'
    """
    label = QLabel(text)
    label.setAlignment(Qt.AlignmentFlag.AlignCenter)

    styles = {
        "critical": f"background-color: rgba(239, 68, 68, 0.2); color: {COLOR_CRITICAL}; border: 1px solid {COLOR_CRITICAL};",
        "high": f"background-color: rgba(249, 115, 22, 0.2); color: {COLOR_HIGH}; border: 1px solid {COLOR_HIGH};",
        "medium": f"background-color: rgba(251, 191, 36, 0.2); color: {COLOR_MEDIUM}; border: 1px solid {COLOR_MEDIUM};",
        "low": f"background-color: rgba(59, 130, 246, 0.2); color: {COLOR_LOW}; border: 1px solid {COLOR_LOW};",
        "success": f"background-color: rgba(16, 185, 129, 0.2); color: {COLOR_SUCCESS}; border: 1px solid {COLOR_SUCCESS};",
        "info": f"background-color: rgba(6, 182, 212, 0.2); color: {COLOR_CYAN}; border: 1px solid {COLOR_CYAN};",
        "active": "background-color: rgba(59, 130, 246, 0.25); color: #60A5FA; border: 1px solid #3B82F6;",
    }

    selected_style = styles.get(badge_type.lower(), styles["info"])
    label.setStyleSheet(
        f"{selected_style} border-radius: 4px; padding: 2px 8px; font-size: 11px; font-weight: 700;"
    )
    return label


def create_metric_card(title: str, value: str, subtitle: str, color: str = COLOR_ACCENT) -> QFrame:
    """Create a prominent stat metric card for command center dashboards."""
    card = create_card_frame()
    layout = QVBoxLayout(card)
    layout.setContentsMargins(16, 16, 16, 16)

    title_lbl = QLabel(title.upper())
    title_lbl.setStyleSheet(f"color: {COLOR_TEXT_MUTED}; font-size: 11px; font-weight: 700; letter-spacing: 0.5px;")

    val_lbl = QLabel(value)
    val_lbl.setStyleSheet(f"color: {color}; font-size: 26px; font-weight: 800; margin-top: 4px;")

    sub_lbl = QLabel(subtitle)
    sub_lbl.setStyleSheet(f"color: {COLOR_TEXT_DIM}; font-size: 11px; margin-top: 2px;")

    layout.addWidget(title_lbl)
    layout.addWidget(val_lbl)
    layout.addWidget(sub_lbl)

    return card
