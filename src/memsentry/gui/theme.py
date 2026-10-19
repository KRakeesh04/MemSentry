"""Shared workspace colors, palettes, and component styling."""

from __future__ import annotations

from PySide6.QtCore import QSettings
from PySide6.QtGui import QColor, QPalette
from PySide6.QtWidgets import QApplication

THEME_DARK = "dark"
THEME_LIGHT = "light"
THEME_SYSTEM = "system"

THEMES = (
    (THEME_DARK, "Dark Theme"),
    (THEME_LIGHT, "Light Theme"),
    (THEME_SYSTEM, "System Default"),
)

_system_palette: QPalette | None = None


def get_system_palette() -> QPalette:
    """Return a copy of the default system palette captured at startup."""
    global _system_palette
    if _system_palette is None:
        app = QApplication.instance()
        if app is not None and isinstance(app, QApplication):
            _system_palette = QPalette(app.palette())
        else:
            _system_palette = QPalette()
    return QPalette(_system_palette)


def create_dark_palette() -> QPalette:
    """Construct a full dark color palette for application surfaces."""
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#11151C"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#E5E7EB"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#1B212B"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#11151C"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#1B212B"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#E5E7EB"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#E5E7EB"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#1B212B"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#E5E7EB"))
    palette.setColor(QPalette.ColorRole.BrightText, QColor("#F87171"))
    palette.setColor(QPalette.ColorRole.Link, QColor("#60A5FA"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#2563EB"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#FFFFFF"))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#A5B0C0"))
    return palette


def create_light_palette() -> QPalette:
    """Construct a full light color palette for application surfaces."""
    palette = QPalette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#F1F5F9"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#172033"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#FFFFFF"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#F8FAFC"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#FFFFFF"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#172033"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#172033"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#FFFFFF"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#172033"))
    palette.setColor(QPalette.ColorRole.BrightText, QColor("#DC2626"))
    palette.setColor(QPalette.ColorRole.Link, QColor("#2563EB"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#2563EB"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#FFFFFF"))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#526174"))
    return palette


def is_dark_theme() -> bool:
    """Determine whether the current application theme is dark."""
    app = QApplication.instance()
    if app is not None and isinstance(app, QApplication):
        return app.palette().color(QPalette.ColorRole.Window).lightness() < 128
    return True


def apply_theme(theme_mode: str, app: QApplication | None = None) -> None:
    """Apply the specified theme mode ('dark', 'light', or 'system') to the application."""
    if app is None:
        instance = QApplication.instance()
        if isinstance(instance, QApplication):
            app = instance
    if app is None:
        return

    # Capture system palette before overriding
    get_system_palette()

    mode = (theme_mode or THEME_DARK).lower().strip()
    if mode == THEME_LIGHT:
        palette = create_light_palette()
    elif mode == THEME_SYSTEM:
        palette = get_system_palette()
    else:
        palette = create_dark_palette()

    app.setPalette(palette)


def get_saved_theme(settings: QSettings | None = None) -> str:
    """Retrieve the saved theme preference from application settings."""
    if settings is None:
        settings = QSettings("MemSentry", "MemSentry")
    return str(settings.value("appearance/theme", THEME_DARK)).lower().strip()


def save_theme(theme_mode: str, settings: QSettings | None = None) -> None:
    """Persist the theme preference to application settings."""
    if settings is None:
        settings = QSettings("MemSentry", "MemSentry")
    settings.setValue("appearance/theme", theme_mode.lower().strip())


def apply_saved_theme(app: QApplication | None = None, settings: QSettings | None = None) -> str:
    """Load and apply the saved theme preference at application launch."""
    saved_theme = get_saved_theme(settings)
    apply_theme(saved_theme, app)
    return saved_theme


def workspace_stylesheet() -> str:
    dark = is_dark_theme()
    background, surface, text, muted, border, accent, selected = (
        ("#11151C", "#1B212B", "#E5E7EB", "#A5B0C0", "#303947", "#60A5FA", "#20334F")
        if dark else
        ("#F1F5F9", "#FFFFFF", "#172033", "#526174", "#DCE3EC", "#2563EB", "#E8F0FE")
    )
    return f"""
        QWidget#workspace {{ background: {background}; color: {text}; }}
        QDialog#analysisDialog {{ background: {surface}; color: {text}; }}
        {'''QDialog#detailsDialog { background: #11151C; color: #E5E7EB; }
        QDialog#detailsDialog QPushButton {
            background: #1B212B; color: #E5E7EB; border: 1px solid #303947;
            border-radius: 6px; padding: 8px 16px;
        }
        QDialog#detailsDialog QPushButton:hover,
        QDialog#detailsDialog QPushButton:focus {
            background: #20334F; border-color: #60A5FA;
        }
        QDialog#detailsDialog QPushButton#primaryButton {
            background: #20334F; color: #60A5FA; border-color: #60A5FA;
        }''' if dark else ''}
        #workspace QListWidget {{
            background: {surface}; color: {text}; border: 1px solid {border};
            border-radius: 6px; selection-background-color: {selected};
            selection-color: {accent}; outline: 0;
        }}
        #workspace QListWidget::item {{ padding: 10px; }}
        #workspace QListWidget#analysisPluginList::item {{ padding: 0px; }}
        #workspace QCheckBox#analysisPluginCheck:hover {{
            background: {selected};
        }}
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
            color: {"#FACC15" if dark else "#785A00"};
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

        #workspace QFrame#findingCard:hover, #workspace QFrame#findingCard:focus {{
            border: 1px solid {accent};
            background: {selected};
        }}
        #workspace QLabel#findingDetailsHint {{ color: {accent}; }}
        #workspace QFrame#successCard {{
            background: {"#182A24" if dark else "#ECFDF5"};
            border: 1px solid {"#2F6B57" if dark else "#86EFAC"};
            border-radius: 10px;
        }}

        #workspace QLabel#successTitle {{
            color: {"#6FCFA9" if dark else "#18734A"};
            font-size: 16px;
            font-weight: bold;
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
        #workspace QLineEdit, #workspace QComboBox, #workspace QTextEdit, #workspace QPlainTextEdit {{
            background: {surface}; color: {text}; border: 1px solid {border};
            border-radius: 6px; padding: 10px; selection-background-color: {selected};
        }}
        #workspace QLineEdit:focus, #workspace QTextEdit:focus, #workspace QPlainTextEdit:focus {{ border-color: {accent}; }}
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
        #workspace QCheckBox, #workspace QRadioButton {{ color: {text}; spacing: 8px; }}
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
            background: {surface}; color: {text}; padding: 16px;
        }}
        #workspace QPushButton#fileDropArea:hover {{ border-color: {accent}; background: {selected}; }}
        #workspace QLabel#systemFieldLabel {{
            color: {muted};
            font-size: 11px;
            font-weight: 600;
        }}

        #workspace QLabel#systemFieldValue {{
            color: {text};
            font-size: 14px;
            font-weight: 500;
        }}
        #workspace QPushButton#graphControlButton {{
            min-width: 34px;
            max-width: 34px;
            min-height: 30px;
            max-height: 30px;

            padding: 0px;

            background-color: {"#182230" if dark else "#FFFFFF"};
            color: {"#CBD5E1" if dark else "#334155"};

            border: 1px solid {"#334155" if dark else "#CBD5E1"};
            border-radius: 6px;

            font-size: 14px;
            font-weight: 600;
        }}

        #workspace QPushButton#graphControlButton:hover {{
            background-color: {"#223043" if dark else "#F1F5F9"};
            color: {"#FFFFFF" if dark else "#0F172A"};
            border-color: {"#475569" if dark else "#94A3B8"};
        }}

        #workspace QPushButton#graphControlButton:pressed {{
            background-color: {"#0F172A" if dark else "#E2E8F0"};
            color: {"#FFFFFF" if dark else "#0F172A"};
            border-color: #3B82F6;
        }}

        #workspace QPushButton#graphControlButton:disabled {{
            background-color: {"#111827" if dark else "#F8FAFC"};
            color: {"#64748B" if dark else "#94A3B8"};
            border-color: {"#253244" if dark else "#E2E8F0"};
        }}


        /* Wider button used for "Fit" */
        #workspace QPushButton#graphFitButton {{
            min-width: 46px;
            max-width: 46px;
            min-height: 30px;
            max-height: 30px;

            padding: 0px 6px;

            background-color: {"#182230" if dark else "#FFFFFF"};
            color: {"#CBD5E1" if dark else "#334155"};

            border: 1px solid {"#334155" if dark else "#CBD5E1"};
            border-radius: 6px;

            font-size: 12px;
            font-weight: 600;
        }}

        #workspace QPushButton#graphFitButton:hover {{
            background-color: {"#223043" if dark else "#F1F5F9"};
            color: {"#FFFFFF" if dark else "#0F172A"};
            border-color: {"#475569" if dark else "#94A3B8"};
        }}

        #workspace QPushButton#graphFitButton:pressed {{
            background-color: {"#0F172A" if dark else "#E2E8F0"};
            color: {"#FFFFFF" if dark else "#0F172A"};
            border-color: #3B82F6;
        }}

        #workspace QPushButton#graphFitButton:disabled {{
            background-color: {"#111827" if dark else "#F8FAFC"};
            color: {"#64748B" if dark else "#94A3B8"};
            border-color: {"#253244" if dark else "#E2E8F0"};
        }}

        QMessageBox, #workspace QMessageBox {{
            background-color: {surface};
            color: {text};
        }}

        QMessageBox QLabel, #workspace QMessageBox QLabel {{
            background-color: transparent;
            color: {text};
            border: none;
        }}

        QMessageBox QLabel#qt_msgbox_label, #workspace QMessageBox QLabel#qt_msgbox_label {{
            background-color: transparent;
            color: {text};
            border: none;
        }}

        QMessageBox QPushButton, #workspace QMessageBox QPushButton {{
            min-width: 90px;
            background-color: {surface};
            color: {text};
            border: 1px solid {border};
            border-radius: 6px;
            padding: 6px 12px;
        }}

        QMessageBox QPushButton:hover, #workspace QMessageBox QPushButton:hover {{
            background-color: {selected};
            color: {text};
            border-color: {accent};
        }}

        QMessageBox QPushButton:pressed, #workspace QMessageBox QPushButton:pressed {{
            background-color: {selected};
            color: {text};
            border-color: {accent};
        }}
        QMessageBox QPushButton:focus, #workspace QMessageBox QPushButton:focus {{
            border-color: {accent};
        }}

        #workspace QGraphicsView#investigationGraphCanvas {{
            background-color: {"#111821" if dark else "#F9FAFB"};
            border: none;
        }}

    """
