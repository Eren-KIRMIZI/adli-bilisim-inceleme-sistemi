"""Design tokens and theme definition for Adli Bilisim Inceleme Sistemi.
Adheres strictly to NIST and forensic suite desktop interface guidelines.
"""

from typing import Dict, Any

# Primary Light Palette (Forensic Standard Light)
LIGHT_THEME: Dict[str, str] = {
    "name": "light",
    "bg": "#F5F5F7",
    "surface": "#FFFFFF",
    "surface_subtle": "#F9FAFB",
    "surface_hover": "#F0F4F8",
    "surface_selected": "#E3ECF5",
    "text": "#1D2733",
    "text_secondary": "#667085",
    "text_muted": "#98A2B3",
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
    "warning": "#B9822D",
    "warning_light": "#FEF7E6",
    "critical": "#C34C4C",
    "critical_light": "#FEE4E2",
    "info": "#2E90FA",
    "info_light": "#EFF8FF",
    "sidebar_bg": "#1D2733",
    "sidebar_text": "#F5F5F7",
    "sidebar_text_muted": "#8A99AC",
    "sidebar_active": "#315C85",
    "sidebar_hover": "#283747",
    "topbar_bg": "#FFFFFF",
    "statusbar_bg": "#1D2733",
    "monospace_font": "'JetBrains Mono', 'Consolas', 'Courier New', monospace",
    "ui_font": "'Segoe UI', 'Inter', -apple-system, sans-serif",
}

# Dark Palette (Forensic Standard Dark - preserves visual hierarchy)
DARK_THEME: Dict[str, str] = {
    "name": "dark",
    "bg": "#111418",
    "surface": "#1A1F26",
    "surface_subtle": "#202630",
    "surface_hover": "#28313E",
    "surface_selected": "#2D3A4B",
    "text": "#E8ECF2",
    "text_secondary": "#9AA5B5",
    "text_muted": "#64748B",
    "border": "#2E3846",
    "border_light": "#252D38",
    "border_focus": "#4A7FA8",
    "accent": "#4A7FA8",
    "accent_hover": "#5C94BF",
    "accent_pressed": "#3A678A",
    "accent_light": "#1C2B38",
    "accent_subtle": "#16202A",
    "verified": "#34A872",
    "verified_light": "#132E22",
    "warning": "#D4973B",
    "warning_light": "#332612",
    "critical": "#D95C5C",
    "critical_light": "#361616",
    "info": "#4B9EF5",
    "info_light": "#122538",
    "sidebar_bg": "#0D1014",
    "sidebar_text": "#E8ECF2",
    "sidebar_text_muted": "#758296",
    "sidebar_active": "#263D52",
    "sidebar_hover": "#171D24",
    "topbar_bg": "#1A1F26",
    "statusbar_bg": "#0D1014",
    "monospace_font": "'JetBrains Mono', 'Consolas', 'Courier New', monospace",
    "ui_font": "'Segoe UI', 'Inter', -apple-system, sans-serif",
}

CURRENT_THEME = "light"

def get_theme(name: str = None) -> Dict[str, str]:
    if name is None:
        name = CURRENT_THEME
    return DARK_THEME if name == "dark" else LIGHT_THEME

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

QWidget {{
    background-color: {t['bg']};
    color: {t['text']};
    selection-background-color: {t['accent_light']};
    selection-color: {t['text']};
}}

/* Window & Base Frames */
QMainWindow {{
    background-color: {t['bg']};
}}

QFrame#surfaceCard {{
    background-color: {t['surface']};
    border: 1px solid {t['border']};
    border-radius: 8px;
}}

QFrame#panelFrame {{
    background-color: {t['surface']};
    border: 1px solid {t['border']};
    border-radius: 6px;
}}

/* Topbar */
QFrame#topbarFrame {{
    background-color: {t['topbar_bg']};
    border-bottom: 1px solid {t['border']};
}}

/* Sidebar */
QFrame#sidebarFrame {{
    background-color: {t['sidebar_bg']};
    border-right: 1px solid {t['border']};
}}

/* Statusbar */
QFrame#statusbarFrame {{
    background-color: {t['statusbar_bg']};
    border-top: 1px solid {t['border']};
    color: {t['sidebar_text_muted']};
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

/* Primary Accent Button */
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

/* Verified / Success Button */
QPushButton#verifiedBtn {{
    background-color: {t['verified']};
    color: #FFFFFF;
    border: none;
}}

/* Danger Button */
QPushButton#dangerBtn {{
    background-color: {t['critical']};
    color: #FFFFFF;
    border: none;
}}

/* Sidebar Navigation Buttons */
QPushButton#navBtn {{
    background-color: transparent;
    color: {t['sidebar_text']};
    border: none;
    border-radius: 6px;
    padding: 8px 12px;
    text-align: left;
    font-size: 13px;
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

/* Tables and Tree Views */
QTableWidget, QTableView, QTreeView {{
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
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDateEdit {{
    background-color: {t['surface']};
    color: {t['text']};
    border: 1px solid {t['border']};
    border-radius: 6px;
    padding: 6px 10px;
}}

QLineEdit:focus, QTextEdit:focus, QPlainTextEdit:focus, QComboBox:focus {{
    border: 1.5px solid {t['border_focus']};
}}

QLineEdit:read-only, QTextEdit:read-only {{
    background-color: {t['surface_subtle']};
    color: {t['text_secondary']};
}}

QComboBox::drop-down {{
    border: none;
    padding-right: 8px;
}}

/* ScrollBars */
QScrollBar:vertical {{
    background: transparent;
    width: 8px;
    margin: 0px;
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
