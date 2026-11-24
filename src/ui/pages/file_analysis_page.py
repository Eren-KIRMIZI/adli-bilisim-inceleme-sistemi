from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, QFileDialog, QTextEdit)
from src.file_engine.file_service import FileAnalysisService
import json

class FileAnalysisPage(QWidget):
    def __init__(self):
        super().__init__()
        v = QVBoxLayout(self)
        row = QHBoxLayout()
        self.path = QLineEdit(); row.addWidget(self.path)
        b = QPushButton("Seç"); b.clicked.connect(lambda: self.path.setText(QFileDialog.getOpenFileName(self)[0])); row.addWidget(b)
        v.addLayout(row)
        btn = QPushButton("Analiz Et"); btn.clicked.connect(self._run); v.addWidget(btn)
        self.out = QTextEdit(); self.out.setReadOnly(True); v.addWidget(self.out)

    def _run(self):
        p = self.path.text()
        if not p: return
        r = FileAnalysisService.analyze(p)
        self.out.setText(json.dumps(r, indent=2, ensure_ascii=False))
