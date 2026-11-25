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
    "border": "#98A2B3",
    "border_light": "#D0D5DD",
    "border_focus": "#315C85",
    "accent": "#315C85",
    "accent_hover": "#1A3D5E",
    "accent_pressed": "#132E47",
    "accent_light": "#E9F1F8",
    "accent_subtle": "#F2F6FA",
    "verified": "#196B47",
    "verified_light": "#EDF7F2",
    "verified_border": "#88CAA9",
    "warning": "#8F5B0B",
    "warning_light": "#FEF7E6",
    "warning_border": "#E9BE67",
    "warning_text": "#724708",
    "critical": "#B42318",
    "critical_light": "#FEE4E2",
    "critical_border": "#F9A8A1",
    "info": "#1D4ED8",
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

# Dark Palette (Flagship Forensic Dark Console — rich slate depth, high-contrast legibility)
DARK_THEME: Dict[str, str] = {
    "name": "dark",
    "bg": "#111418",
    "surface": "#181E27",
    "surface_subtle": "#1E2632",
    "surface_hover": "#252F3E",
    "surface_selected": "#2A394D",
    "text": "#F1F5F9",
    "text_secondary": "#CBD5E1",
    "text_muted": "#94A3B8",
    "border": "#334155",
    "border_light": "#242D3B",
    "border_focus": "#38BDF8",
    "accent": "#3B82F6",
    "accent_hover": "#60A5FA",
    "accent_pressed": "#2563EB",
    "accent_light": "#16263A",
    "accent_subtle": "#142131",
    "verified": "#4ADE80",
    "verified_light": "#122B22",
    "verified_border": "#1F513D",
    "warning": "#FBBF24",
    "warning_light": "#2E220F",
    "warning_border": "#78571E",
    "warning_text": "#FDE68A",
    "critical": "#F87171",
    "critical_light": "#34161A",
    "critical_border": "#7F2F37",
    "info": "#38BDF8",
    "info_light": "#13283D",
    "info_border": "#1E4B72",
    "sidebar_bg": "#0D1014",
    "sidebar_text": "#E8ECF2",
    "sidebar_text_muted": "#8A99AC",
    "sidebar_active": "#1E2D3E",
    "sidebar_hover": "#161C24",
    "sidebar_border": "#1D2531",
    "topbar_bg": "#141920",
    "statusbar_bg": "#0D1014",
    "statusbar_text": "#94A3B8",
    "monospace_font": "'JetBrains Mono', 'Consolas', 'Courier New', monospace",
    "ui_font": "'Segoe UI', 'Inter', -apple-system, sans-serif",
}

CURRENT_THEME = "dark"


def get_theme(name: str = None) -> Dict[str, str]:
    if name is None:
        name = CURRENT_THEME
    return LIGHT_THEME if name == "light" else DARK_THEME


def build_palette(theme_name: str = "dark") -> QPalette:
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


def build_qss(theme_name: str = "dark") -> str:
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
    font-size: 19px;
    font-weight: 700;
    color: {t['text']};
    letter-spacing: -0.2px;
}}

QLabel#cardSub {{
    font-size: 11px;
    font-weight: 500;
    color: {t['text_secondary']};
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

/* Cards & Panels — Soft Hairline Elevation */
QFrame#surfaceCard {{
    background-color: {t['surface']};
    border: 1px solid {t['border_light']};
    border-radius: 10px;
}}

QFrame#kpiCardAccent {{
    background-color: {t['surface']};
    border: 1px solid {t['border_light']};
    border-left: 4px solid {t['accent']};
    border-radius: 10px;
}}

QFrame#kpiCardVerified {{
    background-color: {t['surface']};
    border: 1px solid {t['border_light']};
    border-left: 4px solid {t['verified']};
    border-radius: 10px;
}}

QFrame#kpiCardWarning {{
    background-color: {t['surface']};
    border: 1px solid {t['border_light']};
    border-left: 4px solid {t['warning']};
    border-radius: 10px;
}}

QFrame#kpiCardInfo {{
    background-color: {t['surface']};
    border: 1px solid {t['border_light']};
    border-left: 4px solid {t['info']};
    border-radius: 10px;
}}

QFrame#subCard {{
    background-color: {t['surface_subtle']};
    border: 1px solid {t['border_light']};
    border-radius: 8px;
}}

QFrame#panelFrame {{
    background-color: {t['surface']};
    border: 1px solid {t['border_light']};
    border-radius: 8px;
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
    border-left: 3px solid transparent;
    border-radius: 8px;
    padding: 9px 12px;
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
    border-left: 3px solid #60A5FA;
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
    background-color: #16A34A;
    color: #FFFFFF;
    border: 1px solid #16A34A;
    font-weight: 600;
}}

QPushButton#dangerBtn {{
    background-color: #DC2626;
    color: #FFFFFF;
    border: 1px solid #DC2626;
    font-weight: 600;
}}

/* Tables and Tree Views — Clean Horizontal Hairline Rows */
QTableWidget, QTableView, QTreeView, QTreeWidget {{
    background-color: {t['surface']};
    color: {t['text']};
    border: 1px solid {t['border_light']};
    border-radius: 8px;
    gridline-color: transparent;
    alternate-background-color: {t['surface_subtle']};
    selection-background-color: {t['surface_selected']};
    selection-color: {t['text']};
}}

QTableWidget::item, QTableView::item {{
    padding: 6px 10px;
    border-bottom: 1px solid {t['border_light']};
}}

QHeaderView::section {{
    background-color: {t['surface_subtle']};
    color: {t['text_secondary']};
    font-weight: 700;
    font-size: 11px;
    letter-spacing: 0.4px;
    padding: 9px 12px;
    border: none;
    border-bottom: 1.5px solid {t['border_light']};
    border-right: none;
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

/* Tabs — Modern Underline Segment Navigation */
QTabWidget::pane {{
    border: 1px solid {t['border_light']};
    border-radius: 8px;
    background-color: {t['surface']};
    top: 0px;
    padding-top: 4px;
}}

QTabBar::tab {{
    background-color: transparent;
    color: {t['text_secondary']};
    border: none;
    border-bottom: 2.5px solid transparent;
    padding: 9px 18px;
    margin-right: 6px;
    border-radius: 6px;
    font-weight: 500;
}}

QTabBar::tab:selected {{
    background-color: {t['accent_subtle']};
    color: {t['accent']};
    font-weight: 700;
    border-bottom: 2.5px solid {t['accent']};
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
