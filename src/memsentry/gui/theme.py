"""Shared workspace colors and component styling."""

from PySide6.QtGui import QPalette
from PySide6.QtWidgets import QApplication


def workspace_stylesheet() -> str:
    dark = QApplication.palette().color(QPalette.ColorRole.Window).lightness() < 128
    background, surface, text, muted, border, accent, selected = (
        ("#11151C", "#1B212B", "#E5E7EB", "#A5B0C0", "#303947", "#60A5FA", "#20334F")
        if dark else
        ("#F1F5F9", "#FFFFFF", "#172033", "#526174", "#DCE3EC", "#2563EB", "#E8F0FE")
    )
    return f"""
        QWidget#workspace {{ background: {background}; color: {text}; }}
        QDialog#analysisDialog {{ background: {surface}; color: {text}; }}
        #workspace QListWidget {{
            background: {surface}; color: {text}; border: 1px solid {border};
            border-radius: 6px; selection-background-color: {selected};
            selection-color: {accent}; outline: 0;
        }}
        #workspace QListWidget::item {{ padding: 10px; }}
        #workspace QScrollArea, #workspace QScrollArea > QWidget > QWidget {{
            background: {background}; border: none;
        }}
        #workspace QLabel {{ color: {text}; background: transparent; }}
        #workspace QScrollArea#workflowScroll,
        #workspace QScrollArea#workflowScroll > QWidget,
        #workspace QScrollArea#workflowScroll > QWidget > QWidget {{
            background: {surface}; border: none;
        }}
        #workspace QLabel#pageTitle {{ font-size: 26px; font-weight: bold; }}
        #workspace QLabel#sectionTitle {{ font-size: 16px; font-weight: bold; }}
        #workspace QLabel#metric {{ font-size: 20px; font-weight: bold; }}
        #workspace QLabel#muted {{ color: {muted}; }}
        #workspace QLabel#verified {{ color: {"#6FCFA9" if dark else "#18734A"}; }}
        #workspace QLabel#integrityWarning {{ color: {"#F5B867" if dark else "#955400"}; }}
        #workspace QPushButton[severity="critical"],
        #workspace QPushButton[severity="high"] {{ border-left: 3px solid #C65C5C; }}
        #workspace QPushButton[severity="medium"] {{ border-left: 3px solid #BD8B3D; }}
        #workspace QLabel#severityBadge {{
            padding: 3px 8px;
            border-radius: 8px;
            font-size: 11px;
            font-weight: 600;
        }}
        #workspace QLabel#severityBadge[severity="critical"] {{
            color: #F87171;
            background: rgba(248, 113, 113, 0.12);
        }}
        #workspace QLabel#severityBadge[severity="high"] {{
                color: #FB923C;
            background: rgba(251, 146, 60, 0.12);
        }}
        #workspace QLabel#severityBadge[severity="medium"] {{
            color: #FACC15;
            background: rgba(250, 204, 21, 0.12);
        }}
        #workspace QLabel#severityBadge[severity="low"] {{
            color: #60A5FA;
            background: rgba(96, 165, 250, 0.12);
        }}

        #workspace QLabel#severityBadge[severity="informational"] {{
            color: #94A3B8;
            background: rgba(148, 163, 184, 0.12);
        }}
        #workspace QFrame#card {{
            background: {surface}; border: 1px solid {border}; border-radius: 10px;
        }}
        #workspace QFrame#findingCard {{
            background: {surface};
            border: 1px solid {border};
            border-radius: 10px;
        }}

        #workspace QFrame#findingCard:hover {{
            border: 1px solid {accent};
            background: {selected};
        }}
        #workspace QLabel#previewBanner, #workspace QLabel#jobStatus {{
            background: {surface}; color: {muted}; padding: 14px 24px;
            border-bottom: 1px solid {border};
        }}
        #workspace QTableWidget {{
            background: {surface}; color: {text}; border: 1px solid {border};
            border-radius: 8px; selection-background-color: {selected};
            selection-color: {accent}; outline: 0;
        }}
        #workspace QTableWidget::item {{ padding: 8px; border-bottom: 1px solid {border}; }}
        #workspace QHeaderView::section {{
            background: {surface}; color: {muted}; padding: 12px 8px;
            border: none; border-bottom: 1px solid {border}; font-weight: bold;
        }}
        #workspace QPushButton {{
            padding: 10px 16px; border-radius: 6px; border: 1px solid {border};
            background: {surface}; color: {muted};
        }}
        #workspace QTableWidget:focus {{ border: 1px solid {accent}; }}
        #workspace QLineEdit, #workspace QComboBox, #workspace QTextEdit {{
            background: {surface}; color: {text}; border: 1px solid {border};
            border-radius: 6px; padding: 10px; selection-background-color: {selected};
        }}
        #workspace QLineEdit:focus, #workspace QTextEdit:focus {{ border-color: {accent}; }}
        #workspace QComboBox {{ combobox-popup: 0; }}
        #workspace QComboBox:focus {{ border-color: {accent}; }}
        #workspace QComboBox QAbstractItemView {{
            background: {surface}; color: {text}; border: 1px solid {border};
            selection-background-color: {selected}; selection-color: {accent};
            outline: 0; padding: 4px;
        }}
        #workspace QComboBox QAbstractItemView::item {{
            background: {surface}; color: {text}; padding: 8px 12px;
            min-height: 22px; border: none;
        }}
        #workspace QComboBox QAbstractItemView::item:selected {{
            background: {selected}; color: {accent};
        }}
        #workspace QComboBox QAbstractItemView::item:disabled {{ color: {muted}; }}
        #workspace QCheckBox {{ color: {text}; spacing: 8px; }}
        #workspace QPushButton:enabled:hover {{ border-color: {accent}; color: {accent}; }}
        #workspace QPushButton#primaryAction:enabled {{
            background: {accent}; color: {background}; font-weight: bold;
        }}
        #workspace QProgressBar {{
            background: {surface}; color: {text}; border: 1px solid {border};
            border-radius: 5px; min-height: 20px; text-align: center;
        }}
        #workspace QProgressBar::chunk {{ background: {accent}; border-radius: 4px; }}
        #workspace QPushButton#choiceCard {{
            background: {surface}; border: 1px solid {border}; border-radius: 10px;
            padding: 0; text-align: left;
        }}
        #workspace QPushButton#choiceCard:checked {{
            background: {selected}; border: 1px solid {accent};
        }}
        #workspace QPushButton#choiceCard:checked QLabel#choiceTitle {{ color: {accent}; }}
        #workspace QLabel#choiceTitle {{ font-weight: bold; }}
        #workspace QPushButton#choiceCard:disabled QLabel {{ color: {muted}; }}
        #workspace QPushButton#choiceCard:focus, #workspace QPushButton#fileDropArea:focus {{
            border: 2px solid {accent};
        }}
        #workspace QPushButton#fileDropArea {{
            border: 2px dashed {border}; border-radius: 10px;
            background: {surface}; color: {text}; padding: 24px;
        }}
        #workspace QPushButton#fileDropArea:hover {{ border-color: {accent}; background: {selected}; }}
    """
