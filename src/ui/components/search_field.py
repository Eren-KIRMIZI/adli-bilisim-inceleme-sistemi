"""Forensic search field with clear action and instant/debounced filtering."""

from PySide6.QtWidgets import QWidget, QHBoxLayout, QLineEdit, QPushButton, QLabel
from PySide6.QtCore import Signal, Qt, QTimer

class ForensicSearchField(QWidget):
    searchChanged = Signal(str)

    def __init__(self, placeholder: str = "Ara (Seri No, VID, PID, İsim, Dosya)...", parent=None):
        super().__init__(parent)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.input = QLineEdit()
        self.input.setPlaceholderText(placeholder)
        self.input.setClearButtonEnabled(True)
        self.input.setStyleSheet("""
            QLineEdit {
                padding: 6px 12px;
                border: 1px solid #D0D5DD;
                border-radius: 6px;
                font-size: 13px;
                background-color: #FFFFFF;
                color: #1D2733;
            }
            QLineEdit:focus {
                border: 1.5px solid #315C85;
            }
        """)

        # Debounce timer (150ms) to ensure smooth performance on large datasets
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.setInterval(150)
        self._timer.timeout.connect(self._emit_search)

        self.input.textChanged.connect(self._on_text_changed)
        layout.addWidget(self.input)

    def _on_text_changed(self, text: str):
        self._timer.start()

    def _emit_search(self):
        self.searchChanged.emit(self.input.text().strip())

    def text(self) -> str:
        return self.input.text().strip()

    def clear(self):
        self.input.clear()
