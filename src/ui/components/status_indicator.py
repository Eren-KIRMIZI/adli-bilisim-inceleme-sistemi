"""Status indicator badge component for digital forensic items."""

from PySide6.QtWidgets import QLabel
from PySide6.QtCore import Qt
from src.ui.styles.tokens import LIGHT_THEME

VARIANTS = {
    "verified": {"bg": "#EDF7F2", "color": "#26845B", "border": "#A3D9C1", "icon": "✓"},
    "warning":  {"bg": "#FEF7E6", "color": "#B9822D", "border": "#F3D38D", "icon": "⚠"},
    "critical": {"bg": "#FEE4E2", "color": "#C34C4C", "border": "#FECDCA", "icon": "✕"},
    "info":     {"bg": "#EFF8FF", "color": "#2E90FA", "border": "#B2DDFF", "icon": "ℹ"},
    "neutral":  {"bg": "#F2F4F7", "color": "#475467", "border": "#D0D5DD", "icon": "•"},
}

class StatusBadge(QLabel):
    """Clean forensic status pill badge."""
    def __init__(self, text: str, variant: str = "neutral", parent=None):
        super().__init__(parent)
        self.set_status(text, variant)

    def set_status(self, text: str, variant: str = "neutral"):
        cfg = VARIANTS.get(variant.lower(), VARIANTS["neutral"])
        self.setText(f"{cfg['icon']} {text}")
        self.setAlignment(Qt.AlignCenter)
        self.setStyleSheet(f"""
            QLabel {{
                background-color: {cfg['bg']};
                color: {cfg['color']};
                border: 1px solid {cfg['border']};
                border-radius: 10px;
                padding: 2px 10px;
                font-size: 11px;
                font-weight: 600;
            }}
        """)
        self.setFixedHeight(22)
