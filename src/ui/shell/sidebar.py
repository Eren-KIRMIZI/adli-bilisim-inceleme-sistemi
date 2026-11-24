from PySide6.QtWidgets import QFrame, QVBoxLayout, QPushButton, QLabel
from PySide6.QtCore import Qt

class Sidebar(QFrame):
    def __init__(self, items, on_select):
        super().__init__()
        self.setFixedWidth(230)
        v = QVBoxLayout(self); v.setContentsMargins(12,16,12,16); v.setSpacing(4)
        t = QLabel("Forensics Suite"); t.setStyleSheet("font-size:16px;font-weight:bold;")
        v.addWidget(t)
        for i,it in enumerate(items):
            b = QPushButton(it); b.setStyleSheet("text-align:left;padding:8px;border:none;background:transparent;")
            b.clicked.connect(lambda checked=False, idx=i: on_select(idx))
            v.addWidget(b)
        v.addStretch()
