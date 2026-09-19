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
        #workspace QScrollArea, #workspace QScrollArea > QWidget > QWidget {{
            background: {background}; border: none;
        }}
        #workspace QLabel {{ color: {text}; background: transparent; }}
        #workspace QLabel#pageTitle {{ font-size: 26px; font-weight: bold; }}
        #workspace QLabel#sectionTitle {{ font-size: 16px; font-weight: bold; }}
        #workspace QLabel#metric {{ font-size: 20px; font-weight: bold; }}
        #workspace QLabel#muted {{ color: {muted}; }}
        #workspace QFrame#card {{
            background: {surface}; border: 1px solid {border}; border-radius: 10px;
        }}
        #workspace QLabel#previewBanner, #workspace QLabel#jobStatus {{
            background: {surface}; color: {muted}; padding: 14px 24px;
            border-bottom: 1px solid {border};
        }}
        #workspace QTableWidget {{
            background: {surface}; color: {text}; border: 1px solid {border};
            border-radius: 8px; selection-background-color: {selected};
            selection-color: {accent};
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
        #workspace QComboBox QAbstractItemView {{ background: {surface}; color: {text}; }}
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
