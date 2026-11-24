from PySide6.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QLabel
from src.case_engine.case_service import CaseService
from src.evidence_engine.evidence_service import EvidenceService

class DashboardPage(QWidget):
    def __init__(self):
        super().__init__()
        v = QVBoxLayout(self)
        h = QHBoxLayout()
        cs = CaseService(); es = EvidenceService()
        for label, val in [("Toplam Vaka", len(cs.list_cases())), ("Toplam Delil", len(es.list_evidence()))]:
            card = QLabel(f"{label}\n{val}"); card.setStyleSheet("font-size:20px;padding:16px;border:1px solid #D0D5DD;border-radius:8px;")
            h.addWidget(card)
        v.addLayout(h)
        v.addStretch()
