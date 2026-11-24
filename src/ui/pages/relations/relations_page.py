from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel
class RelationsPage(QWidget):
    def __init__(self):
        super().__init__(); v=QVBoxLayout(self)
        v.addWidget(QLabel("Evidence Relations (placeholder)")); v.addStretch()
