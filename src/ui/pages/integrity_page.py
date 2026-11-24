from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QLabel, QLineEdit, QFileDialog, QMessageBox)
from src.integrity_engine.integrity_service import IntegrityService

class IntegrityPage(QWidget):
    def __init__(self):
        super().__init__()
        v = QVBoxLayout(self)
        row = QHBoxLayout()
        self.path = QLineEdit(); row.addWidget(self.path)
        b = QPushButton("Seç"); b.clicked.connect(lambda: self.path.setText(QFileDialog.getOpenFileName(self)[0])); row.addWidget(b)
        v.addLayout(row)
        btn = QPushButton("SHA-256 Hesapla"); btn.clicked.connect(self._hash); v.addWidget(btn)
        self.out = QLabel(""); v.addWidget(self.out)
        self.verify_row = QHBoxLayout()
        self.exp = QLineEdit(); self.verify_row.addWidget(self.exp)
        vb = QPushButton("Doğrula"); vb.clicked.connect(self._verify); self.verify_row.addWidget(vb)
        v.addLayout(self.verify_row)

    def _hash(self):
        p = self.path.text()
        if not p: return
        self.out.setText(IntegrityService.hash_file(p, "sha256"))

    def _verify(self):
        p = self.path.text(); e = self.exp.text()
        if not p or not e: return
        ok = IntegrityService.verify(p, e)
        QMessageBox.information(self, "Sonuç", "Eşleşti" if ok else "Eşleşmedi")
