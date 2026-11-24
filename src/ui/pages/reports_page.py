from PySide6.QtWidgets import (QWidget, QVBoxLayout, QPushButton, QLineEdit, QFileDialog, QMessageBox)
from src.report_engine.report_service import ReportService

class ReportsPage(QWidget):
    def __init__(self):
        super().__init__()
        v = QVBoxLayout(self)
        self.title = QLineEdit(); self.title.setPlaceholderText("Rapor başlığı"); v.addWidget(self.title)
        self.body = QLineEdit(); self.body.setPlaceholderText("İçerik (tek satır)"); v.addWidget(self.body)
        b = QPushButton("PDF Oluştur"); b.clicked.connect(self._gen); v.addWidget(b)

    def _gen(self):
        path = QFileDialog.getSaveFileName(self, "Kaydet", "report.pdf", "PDF (*.pdf)")[0]
        if not path: return
        ReportService.generate_pdf(path, self.title.text() or "Rapor", [self.body.text()])
        QMessageBox.information(self, "OK", path)
