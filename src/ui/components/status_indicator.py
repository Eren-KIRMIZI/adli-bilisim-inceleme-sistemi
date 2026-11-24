"""Status indicator badge component for digital forensic items."""

from PySide6.QtWidgets import QLabel
from PySide6.QtCore import Qt

VARIANTS = {
    "verified": {"bg": "#EDF7F2", "color": "#1E6B48", "border": "#9CD3B8", "icon": "✓"},
    "warning":  {"bg": "#FEF7E6", "color": "#9A6719", "border": "#F0CA7A", "icon": "⚠"},
    "critical": {"bg": "#FEE4E2", "color": "#B43C3C", "border": "#F9B8B4", "icon": "✕"},
    "info":     {"bg": "#EFF6FF", "color": "#1D4ED8", "border": "#BFDBFE", "icon": "ℹ"},
    "neutral":  {"bg": "#F2F4F7", "color": "#344054", "border": "#D0D5DD", "icon": "•"},
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
        self.setFixedHeight(24)
