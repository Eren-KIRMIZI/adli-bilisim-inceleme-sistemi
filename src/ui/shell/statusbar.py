from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel

class Statusbar(QFrame):
    def __init__(self):
        super().__init__(); self.setFixedHeight(28)
        h = QHBoxLayout(self); h.setContentsMargins(12, 4, 12, 4)
        h.addWidget(QLabel("Salt okunur analiz")); h.addStretch(); h.addWidget(QLabel("Hazır"))
