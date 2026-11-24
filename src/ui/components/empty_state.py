"""Empty and placeholder state visual indicator."""

from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton
from PySide6.QtCore import Qt

class EmptyState(QWidget):
    def __init__(self, title: str = "Kayıt Bulunamadı", 
                 description: str = "Bu filtreye uygun herhangi bir dijital delil veya artefakt tespit edilmedi.",
                 icon: str = "📁", 
                 action_text: str = None, 
                 on_action = None, 
                 parent = None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setAlignment(Qt.AlignCenter)
        layout.setContentsMargins(32, 48, 32, 48)
        layout.setSpacing(12)

        icon_lbl = QLabel(icon)
        icon_lbl.setAlignment(Qt.AlignCenter)
        icon_lbl.setStyleSheet("font-size: 36px; background: transparent;")
        layout.addWidget(icon_lbl)

        title_lbl = QLabel(title)
        title_lbl.setAlignment(Qt.AlignCenter)
        title_lbl.setStyleSheet("font-size: 16px; font-weight: 600; color: #1D2733;")
        layout.addWidget(title_lbl)

        desc_lbl = QLabel(description)
        desc_lbl.setAlignment(Qt.AlignCenter)
        desc_lbl.setWordWrap(True)
        desc_lbl.setStyleSheet("font-size: 13px; color: #667085; max-width: 420px;")
        layout.addWidget(desc_lbl)

        if action_text and on_action:
            btn = QPushButton(action_text)
            btn.setObjectName("primaryBtn")
            btn.clicked.connect(on_action)
            btn.setFixedWidth(180)
            layout.addWidget(btn, alignment=Qt.AlignCenter)
