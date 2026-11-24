"""Main application shell window coordinating topbar, sidebar, pages, and statusbar."""

from PySide6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QStackedWidget, QApplication
)
from src.ui.shell.topbar import Topbar
from src.ui.shell.sidebar import Sidebar
from src.ui.shell.statusbar import Statusbar
from src.ui.styles.tokens import build_qss
from src.case_engine.case_service import CaseService
from src.evidence_engine.evidence_service import EvidenceService


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Adli Bilişim İnceleme Sistemi (Digital Forensics Suite)")
        self.resize(1400, 880)
        self.setMinimumSize(1100, 700)

        self.active_case_id = None
        self.active_evidence_id = None

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
        self.sidebar.pageChanged.connect(self._on_page_changed)
        self._init_pages()
        self._sync_initial_context()

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

        # Global case & evidence synchronization signals
        self.cases_page.activeCaseSelected.connect(self._on_active_case_changed)
        self.evidence_page.activeEvidenceSelected.connect(self._on_active_evidence_changed)

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
            self.settings_page,
        ]

        for p in pages:
            self.stack.addWidget(p)

    def _sync_initial_context(self):
        cases = CaseService().list_cases()
        if cases:
            c = cases[0]
            self._on_active_case_changed(c.id, c.case_number, c.title)
            evds = EvidenceService().list_evidence(case_id=c.id)
            if evds:
                e = evds[0]
                self._on_active_evidence_changed(e.id, f"{e.evidence_number} ({e.brand} {e.model})")

    def _on_active_case_changed(self, case_id: int, case_number: str, title: str):
        self.active_case_id = case_id
        self.topbar.set_active_case(case_number, title)
        evd_count = len(EvidenceService().list_evidence(case_id=case_id))
        self.statusbar.set_case_info(f"Aktif Vaka: {case_number} • Delil Sayısı: {evd_count}")
        self.dashboard_page.set_active_case(case_id)
        self.evidence_page.set_case_context(case_id)

    def _on_active_evidence_changed(self, evidence_id: int, label: str):
        self.active_evidence_id = evidence_id
        self.topbar.set_active_evidence(label)

    def _on_page_changed(self, index: int):
        self.stack.setCurrentIndex(index)
        page = self.stack.widget(index)
        if hasattr(page, "refresh_data"):
            page.refresh_data()
        elif hasattr(page, "refresh_records"):
            page.refresh_records()

    def set_theme(self, theme_name: str):
        qss_code = build_qss(theme_name)
        app = QApplication.instance()
        if app:
            app.setStyleSheet(qss_code)

    def _on_case_switch_clicked(self):
        self.sidebar.select_page(1)
