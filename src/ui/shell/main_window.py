from PySide6.QtWidgets import (QMainWindow, QWidget, QHBoxLayout, QStackedWidget, QLabel, QFrame, QPushButton, QVBoxLayout)
from PySide6.QtCore import Qt

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Adli Bilişim İnceleme Sistemi")
        self.resize(1280, 800)
        central = QWidget()
        self.setCentralWidget(central)
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        self.stack = QStackedWidget()
        self.sidebar = self._build_sidebar()
        layout.addWidget(self.sidebar)
        layout.addWidget(self.stack, 1)

        self._add_pages()
        self._wire_sidebar()

    def _build_sidebar(self):
        frame = QFrame()
        frame.setFixedWidth(230)
        frame.setStyleSheet("background:#1D2733; color:#F5F5F7;")
        v = QVBoxLayout(frame)
        v.setContentsMargins(12, 16, 12, 16)
        v.setSpacing(4)
        title = QLabel("Forensics Suite")
        title.setStyleSheet("font-size:16px;font-weight:bold;color:#F5F5F7;")
        v.addWidget(title)
        self._nav_buttons = []
        items = ["Dashboard", "Cases", "Evidence", "Integrity", "Disk Forensics", "Windows Forensics", "USB Analysis", "Browser Analysis", "Memory Analysis", "File Analysis", "Timeline", "Evidence Relations", "Reports", "Settings"]
        for it in items:
            btn = QPushButton(it)
            btn.setStyleSheet("text-align:left;padding:8px;border:none;color:#F5F5F7;background:transparent;")
            v.addWidget(btn)
            self._nav_buttons.append(btn)
        v.addStretch()
        return frame

    def _add_pages(self):
        from PySide6.QtWidgets import QLabel
        def lbl(t):
            l = QLabel(t); l.setAlignment(Qt.AlignCenter); l.setStyleSheet("font-size:24px;"); return l
        from src.ui.pages.cases_page import CasesPage
        from src.ui.pages.evidence_page import EvidencePage
        from src.ui.pages.integrity_page import IntegrityPage
        from src.ui.pages.file_analysis_page import FileAnalysisPage
        from src.ui.pages.timeline_page import TimelinePage
        from src.ui.pages.reports_page import ReportsPage
        pages = [
            lbl("Dashboard"),
            CasesPage(),
            EvidencePage(),
            IntegrityPage(),
            lbl("Disk Forensics (placeholder)"),
            lbl("Windows Forensics (placeholder)"),
            lbl("USB Analysis (placeholder)"),
            lbl("Browser Analysis (placeholder)"),
            lbl("Memory Analysis (placeholder)"),
            FileAnalysisPage(),
            TimelinePage(),
            lbl("Evidence Relations (placeholder)"),
            ReportsPage(),
            lbl("Settings (placeholder)"),
        ]
        for p in pages:
            self.stack.addWidget(p)

    def _wire_sidebar(self):
        for i, btn in enumerate(self._nav_buttons):
            btn.clicked.connect(lambda checked=False, idx=i: self.stack.setCurrentIndex(idx))
