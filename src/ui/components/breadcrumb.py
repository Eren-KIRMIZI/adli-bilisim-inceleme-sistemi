"""Breadcrumb navigation widget for deep forensic artifact hierarchy."""

from PySide6.QtWidgets import QWidget, QHBoxLayout, QLabel


class Breadcrumb(QWidget):
    def __init__(self, items=None, parent=None):
        super().__init__(parent)
        self.layout = QHBoxLayout(self)
        self.layout.setContentsMargins(0, 0, 0, 0)
        self.layout.setSpacing(6)
        self.set_items(items or ["Adli Bilişim"])

    def set_items(self, items: list[str]):
        while self.layout.count():
            item = self.layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for i, text in enumerate(items):
            lbl = QLabel(text)
            is_last = (i == len(items) - 1)
            lbl.setObjectName("breadcrumbActive" if is_last else "breadcrumbParent")
            self.layout.addWidget(lbl)

            if not is_last:
                sep = QLabel("›")
                sep.setObjectName("breadcrumbSep")
                self.layout.addWidget(sep)

        self.layout.addStretch()
