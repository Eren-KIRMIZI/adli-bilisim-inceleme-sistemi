"""Status indicator badge component for digital forensic items."""

from PySide6.QtWidgets import QLabel
from PySide6.QtCore import Qt

VARIANTS = {
    "verified": {"bg": "#EDF7F2", "color": "#185E3F", "border": "#88CAA9", "icon": "✓"},
    "warning":  {"bg": "#FEF7E6", "color": "#8A5300", "border": "#E9BE67", "icon": "⚠"},
    "critical": {"bg": "#FEE4E2", "color": "#A61B1B", "border": "#F9A8A1", "icon": "✕"},
    "info":     {"bg": "#EFF6FF", "color": "#1E40AF", "border": "#93C5FD", "icon": "ℹ"},
    "neutral":  {"bg": "#F2F4F7", "color": "#1D2939", "border": "#98A2B3", "icon": "•"},
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
