from PySide6.QtWidgets import QFrame, QHBoxLayout, QLabel

class Topbar(QFrame):
    def __init__(self):
        super().__init__()
        self.setFixedHeight(56)
        h = QHBoxLayout(self); h.setContentsMargins(16,8,16,8)
        h.addWidget(QLabel("Adli Bilişim İnceleme Sistemi"))
        h.addStretch()
        h.addWidget(QLabel("v0.1"))

class Statusbar(QFrame):
    def __init__(self):
        super().__init__()
        self.setFixedHeight(28)
        h = QHBoxLayout(self); h.setContentsMargins(12,4,12,4)
        h.addWidget(QLabel("Salt okunur analiz"))
        h.addStretch()
        h.addWidget(QLabel("Hazır"))
