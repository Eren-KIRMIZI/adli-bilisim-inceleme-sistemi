from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QTableWidget, QTableWidgetItem, QLineEdit, QLabel)
from src.timeline_engine.timeline_service import TimelineService

class TimelinePage(QWidget):
    def __init__(self):
        super().__init__()
        self.svc = TimelineService()
        v = QVBoxLayout(self)
        row = QHBoxLayout()
        self.type = QLineEdit(); self.type.setPlaceholderText("Olay türü"); row.addWidget(self.type)
        self.ts = QLineEdit(); self.ts.setPlaceholderText("Zaman (ISO)"); row.addWidget(self.ts)
        self.src = QLineEdit(); self.src.setPlaceholderText("Kaynak"); row.addWidget(self.src)
        b = QPushButton("Ekle"); b.clicked.connect(self._add); row.addWidget(b)
        v.addLayout(row)
        self.table = QTableWidget(0,4); self.table.setHorizontalHeaderLabels(["Tür","Zaman","Kaynak","Detay"])
        v.addWidget(self.table)

    def _add(self):
        self.svc.add(self.type.text(), self.ts.text(), self.src.text())
        self._refresh()

    def _refresh(self):
        evs = self.svc.list()
        self.table.setRowCount(len(evs))
        for i,e in enumerate(evs):
            self.table.setItem(i,0,QTableWidgetItem(e["event_type"]))
            self.table.setItem(i,1,QTableWidgetItem(e["timestamp"]))
            self.table.setItem(i,2,QTableWidgetItem(e["source"]))
            self.table.setItem(i,3,QTableWidgetItem(e["details"]))
