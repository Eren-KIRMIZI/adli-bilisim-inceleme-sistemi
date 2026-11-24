from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QTableWidget, QTableWidgetItem, QDialog, QLineEdit, QTextEdit, QLabel, QMessageBox)
from src.case_engine.case_service import CaseService

class CasesPage(QWidget):
    def __init__(self):
        super().__init__()
        self.svc = CaseService()
        v = QVBoxLayout(self)
        top = QHBoxLayout()
        btn = QPushButton("Yeni Vaka")
        btn.clicked.connect(self._new)
        top.addWidget(btn)
        top.addStretch()
        v.addLayout(top)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["ID", "Vaka No", "Başlık", "Sorumlu", "Durum"])
        v.addWidget(self.table)
        self._refresh()

    def _refresh(self):
        cases = self.svc.list_cases()
        self.table.setRowCount(len(cases))
        for i, c in enumerate(cases):
            self.table.setItem(i, 0, QTableWidgetItem(str(c.id)))
            self.table.setItem(i, 1, QTableWidgetItem(c.case_number))
            self.table.setItem(i, 2, QTableWidgetItem(c.title))
            self.table.setItem(i, 3, QTableWidgetItem(c.investigator or ""))
            self.table.setItem(i, 4, QTableWidgetItem(c.status))

    def _new(self):
        d = QDialog(self)
        d.setWindowTitle("Yeni Vaka")
        v = QVBoxLayout(d)
        v.addWidget(QLabel("Vaka No"))
        num = QLineEdit(); v.addWidget(num)
        v.addWidget(QLabel("Başlık"))
        title = QLineEdit(); v.addWidget(title)
        v.addWidget(QLabel("Sorumlu"))
        inv = QLineEdit(); v.addWidget(inv)
        v.addWidget(QLabel("Açıklama"))
        desc = QTextEdit(); v.addWidget(desc)
        b = QPushButton("Oluştur"); v.addWidget(b)
        def create():
            if not num.text() or not title.text():
                QMessageBox.warning(d, "Hata", "Vaka no ve başlık zorunlu")
                return
            self.svc.create_case(num.text(), title.text(), inv.text(), desc.toPlainText())
            d.accept()
            self._refresh()
        b.clicked.connect(create)
        d.exec()
