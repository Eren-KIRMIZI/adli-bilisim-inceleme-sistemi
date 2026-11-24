"""Breadcrumb navigation widget for deep forensic artifact hierarchy."""

from PySide6.QtWidgets import QWidget, QHBoxLayout, QLabel
from PySide6.QtCore import Qt

class Breadcrumb(QWidget):
    def __init__(self, items=None, parent=None):
        super().__init__(parent)
        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(6)
        self.set_items(items or ["Adli Bilişim"])

    def set_items(self, items: list[str]):
        # Clear existing
        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for i, text in enumerate(items):
            lbl = QLabel(text)
            is_last = (i == len(items) - 1)
            if is_last:
                lbl.setStyleSheet("font-size: 13px; font-weight: 600; color: #1D2733;")
            else:
                lbl.setStyleSheet("font-size: 13px; color: #667085;")
            self.layout.addWidget(lbl)

            if not is_last:
                sep = QLabel("›")
                sep.setStyleSheet("font-size: 14px; color: #98A2B3;")
                self.layout.addWidget(sep)

        self.layout.addStretch()
