from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem,
    QDialog, QLineEdit, QLabel, QComboBox, QMessageBox)
from src.evidence_engine.evidence_service import EvidenceService
from src.case_engine.case_service import CaseService

class EvidencePage(QWidget):
    def __init__(self):
        super().__init__()
        self.svc = EvidenceService()
        self.cases = CaseService()
        v = QVBoxLayout(self)
        top = QHBoxLayout()
        btn = QPushButton("Yeni Delil")
        btn.clicked.connect(self._new)
        top.addWidget(btn); top.addStretch()
        v.addLayout(top)
        self.table = QTableWidget(0, 7)
        self.table.setHorizontalHeaderLabels(["ID","Vaka ID","Tür","Marka","Model","Seri No","Durum"])
        v.addWidget(self.table)
        self._refresh()

    def _refresh(self):
        items = self.svc.list_evidence()
        self.table.setRowCount(len(items))
        for i,e in enumerate(items):
            self.table.setItem(i,0,QTableWidgetItem(str(e.id)))
            self.table.setItem(i,1,QTableWidgetItem(str(e.case_id)))
            self.table.setItem(i,2,QTableWidgetItem(e.device_type or ""))
            self.table.setItem(i,3,QTableWidgetItem(e.brand or ""))
            self.table.setItem(i,4,QTableWidgetItem(e.model or ""))
            self.table.setItem(i,5,QTableWidgetItem(e.serial or ""))
            self.table.setItem(i,6,QTableWidgetItem(e.status))

    def _new(self):
        cases = self.cases.list_cases()
        if not cases:
            QMessageBox.warning(self,"Hata","Önce vaka oluşturun"); return
        d = QDialog(self); d.setWindowTitle("Yeni Delil")
        v = QVBoxLayout(d)
        v.addWidget(QLabel("Vaka"))
        cb = QComboBox()
        for c in cases: cb.addItem(f"{c.id} - {c.case_number}", c.id)
        v.addWidget(cb)
        v.addWidget(QLabel("Tür"))
        typ = QLineEdit(); v.addWidget(typ)
        v.addWidget(QLabel("Marka"))
        brand = QLineEdit(); v.addWidget(brand)
        v.addWidget(QLabel("Model"))
        model = QLineEdit(); v.addWidget(model)
        v.addWidget(QLabel("Seri No"))
        serial = QLineEdit(); v.addWidget(serial)
        v.addWidget(QLabel("Teslim Alan"))
        cust = QLineEdit(); v.addWidget(cust)
        b = QPushButton("Ekle"); v.addWidget(b)
        def create():
            if not typ.text():
                QMessageBox.warning(d,"Hata","Tür zorunlu"); return
            self.svc.add_evidence(cb.currentData(), typ.text(), brand.text(), model.text(), serial.text(), cust.text())
            d.accept(); self._refresh()
        b.clicked.connect(create); d.exec()
