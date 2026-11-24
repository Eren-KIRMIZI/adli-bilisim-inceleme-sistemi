from PySide6.QtWidgets import QWidget, QVBoxLayout, QLabel

def make_page(title):
    w = QWidget(); v = QVBoxLayout(w); l = QLabel(title); l.setStyleSheet("font-size:24px;"); v.addWidget(l); v.addStretch(); return w
