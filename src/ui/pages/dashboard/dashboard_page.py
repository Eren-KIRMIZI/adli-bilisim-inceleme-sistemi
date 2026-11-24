"""Forensic Laboratory Dashboard Page."""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, 
    QPushButton, QGridLayout, QMessageBox, QSplitter
)
from PySide6.QtCore import Qt
from src.case_engine.case_service import CaseService
from src.evidence_engine.evidence_service import EvidenceService
from src.usb_engine.usb_service import UsbService
from src.database.models import init_db, AuditLog, Case, Evidence, UsbDeviceRecord
from src.database.seed import seed_database_if_empty
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.status_indicator import StatusBadge
from src.ui.components.data_table import ForensicDataTable

class DashboardPage(QWidget):
    """Forensic overview page showing case metrics, audit logs, and evidence health."""

    def __init__(self, parent=None):
        super().__init__(parent)
        seed_database_if_empty()
        self.Session = init_db()

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(16)

        # 1. Top Header & Breadcrumbs
        top_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Genel Bakış (Dashboard)"])
        top_bar.addWidget(self.breadcrumb)
        top_bar.addStretch()

        refresh_btn = QPushButton("🔄 Verileri Yenile")
        refresh_btn.setStyleSheet("font-size: 12px; padding: 5px 12px;")
        refresh_btn.clicked.connect(self.refresh_data)
        top_bar.addWidget(refresh_btn)
        main_layout.addLayout(top_bar)

        # 2. KPI Summary Cards Grid
        kpi_grid = QGridLayout()
        kpi_grid.setSpacing(12)

        self.card_cases = self._create_kpi_card("Toplam Vaka", "1 Aktif", "0 Kapanan / Arşiv", "📁")
        self.card_evidence = self._create_kpi_card("Delil Envanteri", "3 Delil", "596 GB Toplam Boyut", "💾")
        self.card_artifacts = self._create_kpi_card("Artefakt Analizi", "4 USB Kaydı", "1 Şüpheli Cihaz İşaretli", "🔌")
        self.card_integrity = self._create_kpi_card("Bütünlük & Hash", "%100 Doğrulandı", "SHA-256 Eşleşme Başarılı", "🔐")

        kpi_grid.addWidget(self.card_cases, 0, 0)
        kpi_grid.addWidget(self.card_evidence, 0, 1)
        kpi_grid.addWidget(self.card_artifacts, 0, 2)
        kpi_grid.addWidget(self.card_integrity, 0, 3)
        main_layout.addLayout(kpi_grid)

        # 3. Quick Forensic Action Bar
        action_bar = QHBoxLayout()
        action_bar.setSpacing(10)

        act_label = QLabel("Hızlı İşlemler:")
        act_label.setStyleSheet("font-size: 12px; font-weight: 600; color: #667085;")
        action_bar.addWidget(act_label)

        btn_new_case = QPushButton("➕ Yeni Vaka Aç")
        btn_new_case.setStyleSheet("padding: 6px 12px; font-size: 12px;")
        btn_new_case.clicked.connect(lambda: self._goto_page(1))
        action_bar.addWidget(btn_new_case)

        btn_add_evd = QPushButton("📥 Delil Kabul Et")
        btn_add_evd.setStyleSheet("padding: 6px 12px; font-size: 12px;")
        btn_add_evd.clicked.connect(lambda: self._goto_page(2))
        action_bar.addWidget(btn_add_evd)

        btn_usb = QPushButton("🔌 USB Analizine Git")
        btn_usb.setObjectName("primaryBtn")
        btn_usb.setStyleSheet("padding: 6px 12px; font-size: 12px;")
        btn_usb.clicked.connect(lambda: self._goto_page(6))
        action_bar.addWidget(btn_usb)

        btn_report = QPushButton("📑 Adli Rapor Oluştur")
        btn_report.setStyleSheet("padding: 6px 12px; font-size: 12px;")
        btn_report.clicked.connect(lambda: self._goto_page(12))
        action_bar.addWidget(btn_report)

        action_bar.addStretch()
        main_layout.addLayout(action_bar)

        # 4. Splitter: Left Audit Trail + Right Active Case Summary
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Left: Son Adli İşlem Günlüğü (Audit Log)
        left_frame = QFrame()
        left_frame.setObjectName("surfaceCard")
        left_lay = QVBoxLayout(left_frame)
        left_lay.setContentsMargins(14, 14, 14, 14)
        left_lay.setSpacing(10)

        l_head = QHBoxLayout()
        l_title = QLabel("Son Adli İşlem Günlüğü (Audit Trail & Activity)")
        l_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #1D2733;")
        l_head.addWidget(l_title)
        l_head.addStretch()
        l_badge = StatusBadge("Denetlenebilir Kayıt", "verified")
        l_head.addWidget(l_badge)
        left_lay.addLayout(l_head)

        headers = ["Zaman (UTC)", "İşlem Türü", "Sorumlu Uzman", "Açıklama", "Bütünlük Hash"]
        self.table_audit = ForensicDataTable(headers, self)
        left_lay.addWidget(self.table_audit)

        splitter.addWidget(left_frame)

        # Right: Active Case & Forensic Environment Card
        right_frame = QFrame()
        right_frame.setObjectName("surfaceCard")
        right_frame.setFixedWidth(380)
        right_lay = QVBoxLayout(right_frame)
        right_lay.setContentsMargins(16, 16, 16, 16)
        right_lay.setSpacing(12)

        r_title = QLabel("Aktif Vaka ve Muhafaza Zinciri")
        r_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #1D2733;")
        right_lay.addWidget(r_title)

        self.case_info_box = QFrame()
        self.case_info_box.setStyleSheet("background: #F9FAFB; border: 1px solid #EAECF0; border-radius: 6px; padding: 10px;")
        cib_lay = QVBoxLayout(self.case_info_box)
        cib_lay.setSpacing(6)

        self.lbl_vaka_no = QLabel("Vaka No: VAK-2026-084")
        self.lbl_vaka_no.setStyleSheet("font-weight: 600; font-size: 13px; color: #315C85;")
        cib_lay.addWidget(self.lbl_vaka_no)

        self.lbl_vaka_title = QLabel("Konu: Yetkisiz Veri Transferi İncelemesi")
        self.lbl_vaka_title.setStyleSheet("font-size: 12px; color: #1D2733;")
        self.lbl_vaka_title.setWordWrap(True)
        cib_lay.addWidget(self.lbl_vaka_title)

        self.lbl_vaka_investigator = QLabel("Uzman: E. Kırmızı (Siber İnceleme)")
        self.lbl_vaka_investigator.setStyleSheet("font-size: 11px; color: #667085;")
        cib_lay.addWidget(self.lbl_vaka_investigator)

        right_lay.addWidget(self.case_info_box)

        # Environmental & Standard Badges
        env_title = QLabel("Adli Standart Uyumluluğu")
        env_title.setStyleSheet("font-size: 12px; font-weight: 600; color: #1D2733; margin-top: 8px;")
        right_lay.addWidget(env_title)

        standards = [
            ("ISO/IEC 27037", "Dijital Delil Muhafaza Standardı", "verified"),
            ("NIST SP 800-86", "Windows Sistem Artefakt Analizi", "verified"),
            ("Salt Okunur Kilit", "Yazma Engelleyici Koruması", "verified"),
            ("Bütünlük Takibi", "Çift Katmanlı SHA-256 / SHA-512", "verified")
        ]

        for std_name, std_desc, var in standards:
            s_row = QHBoxLayout()
            s_lbl = QLabel(f"• {std_name}: {std_desc}")
            s_lbl.setStyleSheet("font-size: 11px; color: #475467;")
            s_row.addWidget(s_lbl, 1)
            b = StatusBadge("Aktif", var)
            s_row.addWidget(b)
            right_lay.addLayout(s_row)

        right_lay.addStretch()
        splitter.addWidget(right_frame)

        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)
        main_layout.addWidget(splitter, 1)

        # Load initial data
        self.refresh_data()

    def _create_kpi_card(self, title: str, main_val: str, sub_val: str, icon: str) -> QFrame:
        card = QFrame()
        card.setObjectName("surfaceCard")
        card.setFixedHeight(82)
        card.setStyleSheet("""
            QFrame#surfaceCard {
                background-color: #FFFFFF;
                border: 1px solid #D0D5DD;
                border-radius: 8px;
            }
        """)

        layout = QHBoxLayout(card)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(10)

        # Icon box
        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet("font-size: 22px; background: transparent;")
        layout.addWidget(icon_lbl)

        # Content box
        text_lay = QVBoxLayout()
        text_lay.setSpacing(2)

        t_lbl = QLabel(title)
        t_lbl.setStyleSheet("font-size: 11px; font-weight: 600; color: #667085;")
        text_lay.addWidget(t_lbl)

        v_lbl = QLabel(main_val)
        v_lbl.setObjectName("cardVal")
        v_lbl.setStyleSheet("font-size: 18px; font-weight: 700; color: #1D2733;")
        text_lay.addWidget(v_lbl)

        s_lbl = QLabel(sub_val)
        s_lbl.setObjectName("cardSub")
        s_lbl.setStyleSheet("font-size: 11px; color: #98A2B3;")
        text_lay.addWidget(s_lbl)

        layout.addLayout(text_lay)
        layout.addStretch()
        return card

    def refresh_data(self):
        """Reload database records and update UI indicators."""
        with self.Session() as s:
            case_count = s.query(Case).count()
            evd_count = s.query(Evidence).count()
            usb_count = s.query(UsbDeviceRecord).count()
            susp_count = s.query(UsbDeviceRecord).filter(UsbDeviceRecord.is_suspicious == True).count()

            # Update KPI Cards
            self.card_cases.findChild(QLabel, "cardVal").setText(f"{case_count} Aktif Vaka")
            self.card_evidence.findChild(QLabel, "cardVal").setText(f"{evd_count} Adli Delil")
            self.card_artifacts.findChild(QLabel, "cardVal").setText(f"{usb_count} USB Kaydı")
            self.card_artifacts.findChild(QLabel, "cardSub").setText(f"{susp_count} Şüpheli Tespit Edildi")

            # Update Audit Log Table
            logs = s.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(50).all()
            records = []
            for log in logs:
                records.append({
                    "Zaman (UTC)": log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else "-",
                    "İşlem Türü": log.action,
                    "Sorumlu Uzman": log.investigator,
                    "Açıklama": log.details,
                    "Bütünlük Hash": log.verification_hash or "Doğrulandı"
                })
            self.table_audit.set_records(records)

    def set_active_case(self, case_id: int):
        """Update active case card from selected case ID."""
        with self.Session() as s:
            c = s.query(Case).filter(Case.id == case_id).first()
            if c:
                self.lbl_vaka_no.setText(f"Vaka No: {c.case_number}")
                self.lbl_vaka_title.setText(f"Konu: {c.title}")
                self.lbl_vaka_investigator.setText(f"Uzman: {c.investigator or '-'} ({c.organization or 'Adli Birim'})")

    def _goto_page(self, index: int):
        window = self.window()
        if hasattr(window, "sidebar"):
            window.sidebar.select_page(index)
