"""Main application shell window coordinating topbar, sidebar, pages, and statusbar."""

import os
from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout, 
    QStackedWidget, QApplication, QMessageBox
)
from PySide6.QtCore import Qt
from src.ui.shell.topbar import Topbar
from src.ui.shell.sidebar import Sidebar
from src.ui.shell.statusbar import Statusbar
from src.ui.styles.tokens import build_qss

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Adli Bilişim İnceleme Sistemi (Digital Forensics Suite)")
        self.resize(1400, 880)
        self.setMinimumSize(1100, 700)

        # Central Container
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        root_layout = QVBoxLayout(central_widget)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Topbar
        self.topbar = Topbar(self)
        self.topbar.themeToggled.connect(self.set_theme)
        self.topbar.caseSwitchRequested.connect(self._on_case_switch_clicked)
        root_layout.addWidget(self.topbar)

        # Main Body: Sidebar + Page Stack
        body_widget = QWidget()
        body_layout = QHBoxLayout(body_widget)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        self.sidebar = Sidebar(self)
        body_layout.addWidget(self.sidebar)

        self.stack = QStackedWidget()
        self.stack.setStyleSheet("background-color: transparent;")
        body_layout.addWidget(self.stack, 1)

        root_layout.addWidget(body_widget, 1)

        # Statusbar
        self.statusbar = Statusbar(self)
        root_layout.addWidget(self.statusbar)

        # Initialize and connect pages
        self.sidebar.pageChanged.connect(self.stack.setCurrentIndex)
        self._init_pages()

        # Apply default Light theme
        self.set_theme("light")

    def _init_pages(self):
        from src.ui.pages.dashboard.dashboard_page import DashboardPage
        from src.ui.pages.cases_page import CasesPage
        from src.ui.pages.evidence_page import EvidencePage
        from src.ui.pages.integrity_page import IntegrityPage
        from src.ui.pages.disk_forensics.disk_forensics_page import DiskForensicsPage
        from src.ui.pages.windows_forensics.windows_forensics_page import WindowsForensicsPage
        from src.ui.pages.usb_analysis.usb_analysis_page import UsbAnalysisPage
        from src.ui.pages.browser_forensics.browser_forensics_page import BrowserAnalysisPage
        from src.ui.pages.memory_forensics.memory_forensics_page import MemoryAnalysisPage
        from src.ui.pages.file_analysis_page import FileAnalysisPage
        from src.ui.pages.timeline_page import TimelinePage
        from src.ui.pages.relations.relations_page import RelationsPage
        from src.ui.pages.reports_page import ReportsPage
        from src.ui.pages.placeholder import make_page

        self.dashboard_page = DashboardPage()
        self.cases_page = CasesPage()
        self.evidence_page = EvidencePage()
        self.integrity_page = IntegrityPage()
        self.disk_page = DiskForensicsPage()
        self.windows_page = WindowsForensicsPage()
        self.usb_page = UsbAnalysisPage()
        self.browser_page = BrowserAnalysisPage()
        self.memory_page = MemoryAnalysisPage()
        self.file_page = FileAnalysisPage()
        self.timeline_page = TimelinePage()
        self.relations_page = RelationsPage()
        self.reports_page = ReportsPage()
        self.settings_page = make_page("Ayarlar ve Lisanslar")

        pages = [
            self.dashboard_page,
            self.cases_page,
            self.evidence_page,
            self.integrity_page,
            self.disk_page,
            self.windows_page,
            self.usb_page,
            self.browser_page,
            self.memory_page,
            self.file_page,
            self.timeline_page,
            self.relations_page,
            self.reports_page,
            self.settings_page
        ]

        for p in pages:
            self.stack.addWidget(p)

    def set_theme(self, theme_name: str):
        qss_code = build_qss(theme_name)
        app = QApplication.instance()
        if app:
            app.setStyleSheet(qss_code)

    def _on_case_switch_clicked(self):
        # Switch to Cases page (index 1)
        self.sidebar.select_page(1)
