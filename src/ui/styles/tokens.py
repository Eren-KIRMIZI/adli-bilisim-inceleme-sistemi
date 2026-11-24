"""Design tokens and theme definition for Adli Bilisim Inceleme Sistemi.
Adheres strictly to NIST and forensic suite desktop interface guidelines.
"""

from typing import Dict
from PySide6.QtGui import QPalette, QColor

# Primary Light Palette (Forensic Standard Light)
LIGHT_THEME: Dict[str, str] = {
    "name": "light",
    "bg": "#F5F5F7",
    "surface": "#FFFFFF",
    "surface_subtle": "#F8FAFC",
    "surface_hover": "#EEF2F6",
    "surface_selected": "#E3ECF5",
    "text": "#1D2733",
    "text_secondary": "#475467",
    "text_muted": "#667085",
    "border": "#D0D5DD",
    "border_light": "#EAECF0",
    "border_focus": "#315C85",
    "accent": "#315C85",
    "accent_hover": "#254869",
    "accent_pressed": "#1A344D",
    "accent_light": "#E9F1F8",
    "accent_subtle": "#F2F6FA",
    "verified": "#26845B",
    "verified_light": "#EDF7F2",
    "verified_border": "#A3D9C1",
    "warning": "#B9822D",
    "warning_light": "#FEF7E6",
    "warning_border": "#F3D38D",
    "warning_text": "#7A5418",
    "critical": "#C34C4C",
    "critical_light": "#FEE4E2",
    "critical_border": "#FECDCA",
    "info": "#2563EB",
    "info_light": "#EFF6FF",
    "info_border": "#BFDBFE",
    "sidebar_bg": "#1D2733",
    "sidebar_text": "#E5E7EB",
    "sidebar_text_muted": "#9CA3AF",
    "sidebar_active": "#315C85",
    "sidebar_hover": "#283747",
    "sidebar_border": "#2A3646",
    "topbar_bg": "#FFFFFF",
    "statusbar_bg": "#1D2733",
    "statusbar_text": "#CBD5E1",
    "monospace_font": "'JetBrains Mono', 'Consolas', 'Courier New', monospace",
    "ui_font": "'Segoe UI', 'Inter', -apple-system, sans-serif",
}

# Dark Palette (Forensic Standard Dark - preserves visual hierarchy with crisp contrast)
DARK_THEME: Dict[str, str] = {
    "name": "dark",
    "bg": "#111418",
    "surface": "#1A1F26",
    "surface_subtle": "#202630",
    "surface_hover": "#28313E",
    "surface_selected": "#2D3A4B",
    "text": "#F1F5F9",
    "text_secondary": "#CBD5E1",
    "text_muted": "#94A3B8",
    "border": "#2E3846",
    "border_light": "#252D38",
    "border_focus": "#4A7FA8",
    "accent": "#3B719F",
    "accent_hover": "#4D87B8",
    "accent_pressed": "#2B567A",
    "accent_light": "#1C2B38",
    "accent_subtle": "#16202A",
    "verified": "#34A872",
    "verified_light": "#132E22",
    "verified_border": "#1E4D38",
    "warning": "#D4973B",
    "warning_light": "#2F2310",
    "warning_border": "#5C431B",
    "warning_text": "#FCD34D",
    "critical": "#D95C5C",
    "critical_light": "#361616",
    "critical_border": "#632525",
    "info": "#60A5FA",
    "info_light": "#16253A",
    "info_border": "#254066",
    "sidebar_bg": "#0D1014",
    "sidebar_text": "#E8ECF2",
    "sidebar_text_muted": "#8A99AC",
    "sidebar_active": "#263D52",
    "sidebar_hover": "#171D24",
    "sidebar_border": "#1F2733",
    "topbar_bg": "#161B22",
    "statusbar_bg": "#0D1014",
    "statusbar_text": "#94A3B8",
    "monospace_font": "'JetBrains Mono', 'Consolas', 'Courier New', monospace",
    "ui_font": "'Segoe UI', 'Inter', -apple-system, sans-serif",
}

CURRENT_THEME = "light"


def get_theme(name: str = None) -> Dict[str, str]:
    if name is None:
        name = CURRENT_THEME
    return DARK_THEME if name == "dark" else LIGHT_THEME


def build_palette(theme_name: str = "light") -> QPalette:
    """Build explicit QPalette so Windows OS dark mode never bleeds into Light Mode widgets."""
    t = get_theme(theme_name)
    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(t["bg"]))
    pal.setColor(QPalette.WindowText, QColor(t["text"]))
    pal.setColor(QPalette.Base, QColor(t["surface"]))
    pal.setColor(QPalette.AlternateBase, QColor(t["surface_subtle"]))
    pal.setColor(QPalette.Text, QColor(t["text"]))
    pal.setColor(QPalette.Button, QColor(t["surface"]))
    pal.setColor(QPalette.ButtonText, QColor(t["text"]))
    pal.setColor(QPalette.Highlight, QColor(t["accent"]))
    pal.setColor(QPalette.HighlightedText, QColor("#FFFFFF"))
    pal.setColor(QPalette.PlaceholderText, QColor(t["text_muted"]))
    return pal


def build_qss(theme_name: str = "light") -> str:
    t = get_theme(theme_name)
    return f"""
/* ==========================================================================
   ADLI BILISIM INCELEME SISTEMI - THEME: {theme_name.upper()}
   ========================================================================== */

* {{
    font-family: {t['ui_font']};
    font-size: 13px;
    outline: none;
}}

QMainWindow, QDialog {{
    background-color: {t['bg']};
    color: {t['text']};
}}

QWidget {{
    color: {t['text']};
}}

QStackedWidget#pageStack {{
    background-color: {t['bg']};
    border: none;
}}

QScrollArea {{
    background-color: transparent;
    border: none;
}}

QScrollArea > QWidget > QWidget {{
    background-color: transparent;
}}

QGraphicsView {{
    background-color: {t['surface']};
    border: 1px solid {t['border_light']};
    border-radius: 6px;
}}

QLabel {{
    background-color: transparent;
    color: {t['text']};
}}

QLabel#sectionTitle {{
    font-size: 13px;
    font-weight: 700;
    color: {t['text']};
}}

QLabel#mutedLabel {{
    font-size: 11px;
    color: {t['text_muted']};
}}

QLabel#monoLabel {{
    font-family: {t['monospace_font']};
    font-size: 11px;
    color: {t['text_secondary']};
}}

QLabel#cardVal {{
    font-size: 18px;
    font-weight: 700;
    color: {t['text']};
}}

QLabel#cardSub {{
    font-size: 11px;
    color: {t['text_muted']};
}}

QLabel#breadcrumbParent {{
    font-size: 13px;
    color: {t['text_muted']};
}}

QLabel#breadcrumbSep {{
    font-size: 14px;
    color: {t['text_muted']};
}}

QLabel#breadcrumbActive {{
    font-size: 13px;
    font-weight: 600;
    color: {t['text']};
}}

/* Cards & Panels */
QFrame#surfaceCard {{
    background-color: {t['surface']};
    border: 1px solid {t['border']};
    border-radius: 8px;
}}

QFrame#subCard {{
    background-color: {t['surface_subtle']};
    border: 1px solid {t['border']};
    border-radius: 6px;
}}

QFrame#panelFrame {{
    background-color: {t['surface']};
    border: 1px solid {t['border']};
    border-radius: 6px;
}}

QFrame#warnBanner {{
    background-color: {t['warning_light']};
    border: 1px solid {t['warning_border']};
    border-radius: 6px;
}}

QLabel#warnBannerText {{
    color: {t['warning_text']};
    font-size: 12px;
    background-color: transparent;
}}

QFrame#infoBanner {{
    background-color: {t['info_light']};
    border: 1px solid {t['info_border']};
    border-radius: 6px;
}}

QLabel#infoBannerText {{
    color: {t['info']};
    font-size: 12px;
    background-color: transparent;
}}

/* Topbar */
QFrame#topbarFrame {{
    background-color: {t['topbar_bg']};
    border-bottom: 1px solid {t['border']};
}}

QLabel#topbarTitle {{
    font-size: 14px;
    font-weight: 700;
    color: {t['text']};
    letter-spacing: 0.5px;
}}

QLabel#topbarBadge {{
    background-color: {t['accent_light']};
    color: {t['accent']};
    font-size: 10px;
    font-weight: 700;
    padding: 3px 7px;
    border-radius: 4px;
}}

QPushButton#topbarCaseBtn {{
    background-color: {t['surface_subtle']};
    color: {t['text']};
    border: 1px solid {t['border']};
    border-radius: 6px;
    padding: 5px 12px;
    font-size: 12px;
    font-weight: 600;
}}

QPushButton#topbarCaseBtn:hover {{
    background-color: {t['surface_hover']};
    border-color: {t['accent']};
}}

QLabel#topbarEvidencePill {{
    background-color: {t['surface_subtle']};
    color: {t['text_secondary']};
    border: 1px solid {t['border_light']};
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
    font-weight: 500;
}}

QLabel#topbarWriteBlockPill {{
    background-color: {t['verified_light']};
    color: {t['verified']};
    border: 1px solid {t['verified_border']};
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 11px;
    font-weight: 700;
}}

QLabel#topbarProfilePill {{
    background-color: {t['sidebar_bg']};
    color: #F5F5F7;
    border: 1px solid {t['sidebar_border']};
    border-radius: 6px;
    padding: 5px 10px;
    font-size: 12px;
    font-weight: 600;
}}

/* Sidebar */
QFrame#sidebarFrame {{
    background-color: {t['sidebar_bg']};
    border-right: 1px solid {t['sidebar_border']};
}}

QWidget#sidebarContainer {{
    background-color: transparent;
}}

QLabel#sidebarHeader {{
    color: {t['sidebar_text_muted']};
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 1px;
    padding: 4px 8px;
}}

QFrame#sidebarFooter {{
    background-color: transparent;
    border: none;
    border-top: 1px solid {t['sidebar_border']};
    padding-top: 8px;
}}

QLabel#sidebarFooterSafe {{
    color: #34A872;
    font-size: 11px;
    font-weight: 600;
}}

QLabel#sidebarFooterVer {{
    color: {t['sidebar_text_muted']};
    font-size: 10px;
}}

QPushButton#navBtn {{
    background-color: transparent;
    color: {t['sidebar_text']};
    border: none;
    border-radius: 6px;
    padding: 8px 12px;
    text-align: left;
    font-size: 13px;
    font-weight: 500;
}}

QPushButton#navBtn:hover {{
    background-color: {t['sidebar_hover']};
    color: #FFFFFF;
}}

QPushButton#navBtn:checked, QPushButton#navBtn[active="true"] {{
    background-color: {t['sidebar_active']};
    color: #FFFFFF;
    font-weight: 600;
}}

/* Statusbar */
QFrame#statusbarFrame {{
    background-color: {t['statusbar_bg']};
    border-top: 1px solid {t['sidebar_border']};
}}

QLabel#statusBarText {{
    font-size: 11px;
    color: {t['statusbar_text']};
    background-color: transparent;
}}

QLabel#statusBarDbOk {{
    font-size: 11px;
    color: #34A872;
    font-weight: 600;
    background-color: transparent;
}}

/* Buttons */
QPushButton {{
    background-color: {t['surface']};
    color: {t['text']};
    border: 1px solid {t['border']};
    border-radius: 6px;
    padding: 6px 14px;
    font-weight: 500;
}}

QPushButton:hover {{
    background-color: {t['surface_hover']};
    border-color: {t['border_focus']};
}}

QPushButton:pressed {{
    background-color: {t['surface_selected']};
}}

QPushButton:disabled {{
    background-color: {t['surface_subtle']};
    color: {t['text_muted']};
    border-color: {t['border_light']};
}}

QPushButton#primaryBtn {{
    background-color: {t['accent']};
    color: #FFFFFF;
    border: 1px solid {t['accent']};
    font-weight: 600;
}}

QPushButton#primaryBtn:hover {{
    background-color: {t['accent_hover']};
    border-color: {t['accent_hover']};
}}

QPushButton#primaryBtn:pressed {{
    background-color: {t['accent_pressed']};
}}

QPushButton#verifiedBtn {{
    background-color: {t['verified']};
    color: #FFFFFF;
    border: 1px solid {t['verified']};
    font-weight: 600;
}}

QPushButton#dangerBtn {{
    background-color: {t['critical']};
    color: #FFFFFF;
    border: 1px solid {t['critical']};
    font-weight: 600;
}}

/* Tables and Tree Views */
QTableWidget, QTableView, QTreeView, QTreeWidget {{
    background-color: {t['surface']};
    color: {t['text']};
    border: 1px solid {t['border']};
    border-radius: 6px;
    gridline-color: {t['border_light']};
    alternate-background-color: {t['surface_subtle']};
    selection-background-color: {t['surface_selected']};
    selection-color: {t['text']};
}}

QHeaderView::section {{
    background-color: {t['surface_subtle']};
    color: {t['text_secondary']};
    font-weight: 600;
    font-size: 12px;
    padding: 6px 10px;
    border: none;
    border-bottom: 1px solid {t['border']};
    border-right: 1px solid {t['border_light']};
}}

QHeaderView::section:hover {{
    background-color: {t['surface_hover']};
}}

/* Inputs */
QLineEdit, QTextEdit, QPlainTextEdit, QTextBrowser, QComboBox, QSpinBox, QDateEdit {{
    background-color: {t['surface']};
    color: {t['text']};
    border: 1px solid {t['border']};
    border-radius: 6px;
    padding: 6px 10px;
}}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{
    border: 1.5px solid {t['border_focus']};
}}

QLineEdit:read-only, QTextEdit:read-only, QPlainTextEdit:read-only {{
    background-color: {t['surface_subtle']};
    color: {t['text_secondary']};
}}

QComboBox QAbstractItemView {{
    background-color: {t['surface']};
    color: {t['text']};
    border: 1px solid {t['border']};
    selection-background-color: {t['surface_selected']};
    selection-color: {t['text']};
}}

QCheckBox {{
    color: {t['text']};
    spacing: 8px;
}}

/* ScrollBars */
QScrollBar:vertical {{
    background: transparent;
    width: 8px;
}}

QScrollBar::handle:vertical {{
    background: {t['border']};
    min-height: 24px;
    border-radius: 4px;
}}

QScrollBar::handle:vertical:hover {{
    background: {t['text_muted']};
}}

QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
    height: 0px;
}}

QScrollBar:horizontal {{
    background: transparent;
    height: 8px;
}}

QScrollBar::handle:horizontal {{
    background: {t['border']};
    min-width: 24px;
    border-radius: 4px;
}}

/* Tabs */
QTabWidget::pane {{
    border: 1px solid {t['border']};
    border-radius: 6px;
    background-color: {t['surface']};
    top: -1px;
}}

QTabBar::tab {{
    background-color: {t['surface_subtle']};
    color: {t['text_secondary']};
    border: 1px solid {t['border']};
    border-bottom: none;
    padding: 7px 16px;
    margin-right: 4px;
    border-top-left-radius: 6px;
    border-top-right-radius: 6px;
}}

QTabBar::tab:selected {{
    background-color: {t['surface']};
    color: {t['accent']};
    font-weight: 600;
    border-bottom: 2px solid {t['accent']};
}}

QTabBar::tab:hover:!selected {{
    background-color: {t['surface_hover']};
    color: {t['text']};
}}

/* Splitters */
QSplitter::handle {{
    background-color: {t['border_light']};
}}

QSplitter::handle:hover {{
    background-color: {t['accent']};
}}

/* Tooltips */
QToolTip {{
    background-color: {t['text']};
    color: {t['bg']};
    border: 1px solid {t['border']};
    padding: 4px 8px;
    border-radius: 4px;
    font-size: 11px;
}}
"""
