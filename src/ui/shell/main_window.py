from PySide6.QtWidgets import QMainWindow, QWidget, QHBoxLayout, QStackedWidget, QLabel, QFrame
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

        self.sidebar = self._build_sidebar()
        layout.addWidget(self.sidebar)

        self.stack = QStackedWidget()
        layout.addWidget(self.stack, 1)

        self._add_pages()

    def _build_sidebar(self):
        frame = QFrame()
        frame.setFixedWidth(230)
        frame.setStyleSheet("background:#1D2733; color:#F5F5F7;")
        from PySide6.QtWidgets import QVBoxLayout, QPushButton
        v = QVBoxLayout(frame)
        v.setContentsMargins(12, 16, 12, 16)
        v.setSpacing(4)
        title = QLabel("Forensics Suite")
        title.setStyleSheet("font-size:16px;font-weight:bold;color:#F5F5F7;")
        v.addWidget(title)
        items = ["Dashboard", "Cases", "Evidence", "Disk Forensics", "Windows Forensics", "USB Analysis", "Browser Analysis", "Memory Analysis", "File Analysis", "Timeline", "Evidence Relations", "Reports", "Settings"]
        for it in items:
            btn = QPushButton(it)
            btn.setStyleSheet("text-align:left;padding:8px;border:none;color:#F5F5F7;background:transparent;")
            v.addWidget(btn)
        v.addStretch()
        return frame

    def _add_pages(self):
        from PySide6.QtWidgets import QLabel
        from src.ui.pages.cases_page import CasesPage
        from src.ui.pages.evidence_page import EvidencePage
        dash = QLabel("Dashboard")
        dash.setAlignment(Qt.AlignCenter)
        dash.setStyleSheet("font-size:24px;")
        self.stack.addWidget(dash)
        self.stack.addWidget(CasesPage())
        self.stack.addWidget(EvidencePage())
