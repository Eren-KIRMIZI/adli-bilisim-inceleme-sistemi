"""Forensic search field with clear action and instant/debounced filtering."""

from PySide6.QtWidgets import QWidget, QHBoxLayout, QLineEdit
from PySide6.QtCore import Signal, QTimer


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
