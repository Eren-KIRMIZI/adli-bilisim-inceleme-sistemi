from PySide6.QtWidgets import (QMainWindow, QWidget, QHBoxLayout, QStackedWidget, QFrame, QPushButton, QVBoxLayout)
from PySide6.QtCore import Qt

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Adli Bilişim İnceleme Sistemi")
        self.resize(1280, 800)
        central = QWidget(); self.setCentralWidget(central)
        layout = QHBoxLayout(central); layout.setContentsMargins(0,0,0,0); layout.setSpacing(0)
        self.stack = QStackedWidget()
        self.sidebar = self._build_sidebar()
        layout.addWidget(self.sidebar); layout.addWidget(self.stack, 1)
        self._add_pages(); self._wire_sidebar()

    def _build_sidebar(self):
        frame = QFrame(); frame.setFixedWidth(230)
        frame.setStyleSheet("background:#1D2733; color:#F5F5F7;")
        v = QVBoxLayout(frame); v.setContentsMargins(12,16,12,16); v.setSpacing(4)
        from PySide6.QtWidgets import QLabel
        t = QLabel("Forensics Suite"); t.setStyleSheet("font-size:16px;font-weight:bold;color:#F5F5F7;")
        v.addWidget(t)
        self._nav_buttons = []
        items = ["Dashboard","Cases","Evidence","Integrity","Disk Forensics","Windows Forensics","USB Analysis","Browser Analysis","Memory Analysis","File Analysis","Timeline","Evidence Relations","Reports","Settings"]
        for it in items:
            b = QPushButton(it); b.setStyleSheet("text-align:left;padding:8px;border:none;color:#F5F5F7;background:transparent;")
            v.addWidget(b); self._nav_buttons.append(b)
        v.addStretch()
        return frame

    def _add_pages(self):
        from src.ui.pages.cases_page import CasesPage
        from src.ui.pages.evidence_page import EvidencePage
        from src.ui.pages.integrity_page import IntegrityPage
        from src.ui.pages.file_analysis_page import FileAnalysisPage
        from src.ui.pages.timeline_page import TimelinePage
        from src.ui.pages.reports_page import ReportsPage
        from src.ui.pages.dashboard.dashboard_page import DashboardPage
        from src.ui.pages.placeholder import make_page
        pages = [DashboardPage(), CasesPage(), EvidencePage(), IntegrityPage(),
                 make_page("Disk Forensics"), make_page("Windows Forensics"),
                 make_page("USB Analysis"), make_page("Browser Analysis"),
                 make_page("Memory Analysis"), FileAnalysisPage(), TimelinePage(),
                 make_page("Evidence Relations"), ReportsPage(), make_page("Settings")]
        for p in pages: self.stack.addWidget(p)

    def _wire_sidebar(self):
        for i, btn in enumerate(self._nav_buttons):
            btn.clicked.connect(lambda checked=False, idx=i: self.stack.setCurrentIndex(idx))
