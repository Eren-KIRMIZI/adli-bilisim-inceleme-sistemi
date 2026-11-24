from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLineEdit, QFileDialog, QTextEdit
from src.registry_engine.registry_engine import BrowserEngine

class BrowserAnalysisPage(QWidget):
    def __init__(self):
        super().__init__(); v=QVBoxLayout(self)
        row=QHBoxLayout(); self.path=QLineEdit(); row.addWidget(self.path)
        b=QPushButton("Seç"); b.clicked.connect(lambda: self.path.setText(QFileDialog.getOpenFileName(self)[0])); row.addWidget(b)
        v.addLayout(row)
        btn=QPushButton("Tabloları Listele"); btn.clicked.connect(self._run); v.addWidget(btn)
        self.out=QTextEdit(); self.out.setReadOnly(True); v.addWidget(self.out)
    def _run(self):
        p=self.path.text()
        if not p: return
        tabs=BrowserEngine().read_sqlite_tables(p)
        self.out.setText("\n".join(tabs))
