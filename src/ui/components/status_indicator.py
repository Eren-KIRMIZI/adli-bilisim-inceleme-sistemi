"""Status indicator badge component for digital forensic items."""

from PySide6.QtWidgets import QLabel
from PySide6.QtCore import Qt

VARIANTS = {
    "verified": {"bg": "#122B22", "color": "#4ADE80", "border": "#1F513D", "icon": "✓"},
    "warning":  {"bg": "#2E220F", "color": "#FBBF24", "border": "#78571E", "icon": "⚠"},
    "critical": {"bg": "#34161A", "color": "#F87171", "border": "#7F2F37", "icon": "✕"},
    "info":     {"bg": "#13283D", "color": "#38BDF8", "border": "#1E4B72", "icon": "ℹ"},
    "neutral":  {"bg": "#1E2632", "color": "#CBD5E1", "border": "#334155", "icon": "•"},
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
