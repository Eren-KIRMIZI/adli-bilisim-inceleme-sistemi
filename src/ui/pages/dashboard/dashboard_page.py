"""Forensic Laboratory Dashboard Page."""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, 
    QPushButton, QGridLayout, QMessageBox, QSplitter, QDialog,
    QFileDialog, QTextEdit
)
from PySide6.QtCore import Qt
from PySide6.QtGui import QPainter, QColor, QPainterPath
from src.case_engine.case_service import CaseService
from src.evidence_engine.evidence_service import EvidenceService
from src.usb_engine.usb_service import UsbService
from src.core.orchestrator import AnalysisOrchestrator
from src.ui.workers import FunctionWorker
from src.ui.styles.icons import get_banner_pixmap, get_brand_pixmap, render_svg_icon
from src.database.models import (
    init_db, AuditLog, Case, Evidence, UsbDeviceRecord, ForensicArtifact, verify_audit_chain
)
from src.database.seed import seed_database_if_empty
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.status_indicator import StatusBadge
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.charts import CircularGaugeWidget, SplineAreaChart


class ForensicLabBanner(QFrame):
    """Sleek rounded hero strip displaying the Gemini Banana lab artwork in Dark Console theme."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setObjectName("surfaceCard")
        self.setFixedHeight(92)
        self._theme_name = "dark"
        self._banner_pix = get_banner_pixmap("dark")

        lay = QHBoxLayout(self)
        lay.setContentsMargins(18, 12, 18, 12)
        lay.setSpacing(14)

        shield = QLabel()
        spix = get_brand_pixmap(48)
        if not spix.isNull():
            shield.setPixmap(spix)
        shield.setFixedSize(52, 52)
        shield.setStyleSheet("background: transparent;")
        lay.addWidget(shield)

        txt_col = QVBoxLayout()
        txt_col.setSpacing(2)
        self.title_lbl = QLabel("Adli Bilişim İnceleme Laboratuvarı")
        self.title_lbl.setStyleSheet("font-size: 16px; font-weight: 700; color: #F8FAFC; background: transparent;")
        self.sub_lbl = QLabel(
            "ISO/IEC 27037 • NIST SP 800-86 • SWGDE • Salt-Okunur Çevrimdışı DFIR Platformu"
        )
        self.sub_lbl.setObjectName("mutedLabel")
        self.sub_lbl.setStyleSheet("font-size: 12px; color: #CBD5E1; background: transparent;")
        txt_col.addWidget(self.title_lbl)
        txt_col.addWidget(self.sub_lbl)
        lay.addLayout(txt_col)
        lay.addStretch()

    def set_theme(self, theme_name: str):
        self._theme_name = "dark"
        self._banner_pix = get_banner_pixmap("dark")
        self.title_lbl.setStyleSheet("font-size: 16px; font-weight: 700; color: #F8FAFC; background: transparent;")
        self.sub_lbl.setStyleSheet("font-size: 12px; color: #CBD5E1; background: transparent;")
        self.update()

    def paintEvent(self, event):
        super().paintEvent(event)
        if self._banner_pix.isNull():
            return
        painter = QPainter(self)
        painter.setRenderHint(QPainter.SmoothPixmapTransform)
        r = self.rect().adjusted(1, 1, -1, -1)
        path = QPainterPath()
        path.addRoundedRect(r, 7, 7)
        painter.setClipPath(path)
        scaled = self._banner_pix.scaled(r.size(), Qt.KeepAspectRatioByExpanding, Qt.SmoothTransformation)
        painter.drawPixmap(r.topLeft(), scaled)

class DashboardPage(QWidget):
    """Forensic overview page showing case metrics, audit logs, and evidence health."""

    def __init__(self, db_path: str = "data/forensics.db", parent=None):
        super().__init__(parent)
        self.db_path = db_path
        seed_database_if_empty(db_path)
        self.Session = init_db(db_path)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(16)

        # 1. Top Header & Breadcrumbs
        top_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Genel Bakış (Dashboard)"])
        top_bar.addWidget(self.breadcrumb)
        top_bar.addStretch()

        refresh_btn = QPushButton(" Verileri Yenile")
        refresh_btn.setIcon(render_svg_icon("integrity", "#CBD5E1", 15))
        refresh_btn.clicked.connect(self.refresh_data)
        top_bar.addWidget(refresh_btn)
        main_layout.addLayout(top_bar)

        # 1b. Gemini Banana Forensic Lab Hero Strip
        self.hero_banner = ForensicLabBanner(self)
        main_layout.addWidget(self.hero_banner)

        # 2. KPI Summary Cards Grid
        kpi_grid = QGridLayout()
        kpi_grid.setSpacing(12)

        self.card_cases = self._create_kpi_card("Toplam Vaka", "-", "Yükleniyor...", "cases", "kpiCardAccent", "#60A5FA", "rgba(59, 130, 246, 0.14)")
        self.card_evidence = self._create_kpi_card("Delil Envanteri", "-", "Yükleniyor...", "evidence", "kpiCardInfo", "#38BDF8", "rgba(56, 189, 248, 0.14)")
        self.card_artifacts = self._create_kpi_card("Artefakt Analizi", "-", "Yükleniyor...", "usb", "kpiCardWarning", "#FBBF24", "rgba(251, 191, 36, 0.14)")
        self.integrity_gauge = CircularGaugeWidget(value=0, accent_color="#4ADE80", size=58, theme_name="dark")
        self.card_integrity = self._create_kpi_card(
            "Bütünlük & Hash", "-", "Yükleniyor...", "integrity", "kpiCardVerified", "#4ADE80", "rgba(74, 222, 128, 0.14)", right_widget=self.integrity_gauge
        )

        kpi_grid.addWidget(self.card_cases, 0, 0)
        kpi_grid.addWidget(self.card_evidence, 0, 1)
        kpi_grid.addWidget(self.card_artifacts, 0, 2)
        kpi_grid.addWidget(self.card_integrity, 0, 3)
        main_layout.addLayout(kpi_grid)

        # 3. Quick Forensic Action Bar
        action_bar = QHBoxLayout()
        action_bar.setSpacing(10)

        act_label = QLabel("Hızlı İşlemler:")
        act_label.setObjectName("mutedLabel")
        action_bar.addWidget(act_label)

        btn_new_case = QPushButton(" Yeni Vaka Aç")
        btn_new_case.setIcon(render_svg_icon("cases", "#60A5FA", 15))
        btn_new_case.clicked.connect(lambda: self._goto_page(1))
        action_bar.addWidget(btn_new_case)

        btn_add_evd = QPushButton(" Delil Kabul Et")
        btn_add_evd.setIcon(render_svg_icon("evidence", "#38BDF8", 15))
        btn_add_evd.clicked.connect(lambda: self._goto_page(2))
        action_bar.addWidget(btn_add_evd)

        btn_usb = QPushButton(" USB Analizine Git")
        btn_usb.setObjectName("primaryBtn")
        btn_usb.setIcon(render_svg_icon("usb", "#FFFFFF", 15))
        btn_usb.clicked.connect(lambda: self._goto_page(6))
        action_bar.addWidget(btn_usb)

        btn_report = QPushButton(" Adli Rapor Oluştur")
        btn_report.setIcon(render_svg_icon("report", "#CBD5E1", 15))
        btn_report.clicked.connect(lambda: self._goto_page(12))
        action_bar.addWidget(btn_report)

        btn_ingest = QPushButton(" Otomatik Analiz Kuyruğu")
        btn_ingest.setIcon(render_svg_icon("timeline", "#4ADE80", 15))
        btn_ingest.clicked.connect(self._open_ingest_dialog)
        action_bar.addWidget(btn_ingest)

        action_bar.addStretch()
        main_layout.addLayout(action_bar)

        # 4. Splitter: Left Audit Trail & Telemetry Curve + Right Active Case Summary
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Left: Forensic Telemetry Curve + Son Adli İşlem Günlüğü
        left_frame = QFrame()
        left_frame.setObjectName("surfaceCard")
        left_lay = QVBoxLayout(left_frame)
        left_lay.setContentsMargins(14, 14, 14, 14)
        left_lay.setSpacing(10)

        l_head = QHBoxLayout()
        l_title = QLabel("Adli İşlem Yoğunluğu & Denetim Günlüğü")
        l_title.setObjectName("sectionTitle")
        l_head.addWidget(l_title)
        l_head.addStretch()
        l_badge = StatusBadge("Denetlenebilir Kayıt", "verified")
        l_head.addWidget(l_badge)
        left_lay.addLayout(l_head)

        self.activity_chart = SplineAreaChart(height=104, theme_name="dark", parent=self)
        left_lay.addWidget(self.activity_chart)

        headers = ["Zaman (UTC)", "İşlem Türü", "Sorumlu Uzman", "Açıklama", "Bütünlük Hash"]
        self.table_audit = ForensicDataTable(headers, self)
        left_lay.addWidget(self.table_audit, 1)

        splitter.addWidget(left_frame)

        # Right: Active Case & Forensic Environment Card
        right_frame = QFrame()
        right_frame.setObjectName("surfaceCard")
        right_frame.setFixedWidth(380)
        right_lay = QVBoxLayout(right_frame)
        right_lay.setContentsMargins(16, 16, 16, 16)
        right_lay.setSpacing(12)

        r_title = QLabel("Aktif Vaka ve Muhafaza Zinciri")
        r_title.setObjectName("sectionTitle")
        right_lay.addWidget(r_title)

        self.case_info_box = QFrame()
        self.case_info_box.setObjectName("subCard")
        cib_lay = QVBoxLayout(self.case_info_box)
        cib_lay.setContentsMargins(12, 10, 12, 10)
        cib_lay.setSpacing(6)

        self.lbl_vaka_no = QLabel("Vaka No: VAK-2026-084")
        self.lbl_vaka_no.setObjectName("sectionTitle")
        cib_lay.addWidget(self.lbl_vaka_no)

        self.lbl_vaka_title = QLabel("Konu: Yetkisiz Veri Transferi İncelemesi")
        self.lbl_vaka_title.setWordWrap(True)
        cib_lay.addWidget(self.lbl_vaka_title)

        self.lbl_vaka_investigator = QLabel("Uzman: E. Kırmızı (Siber İnceleme)")
        self.lbl_vaka_investigator.setObjectName("mutedLabel")
        cib_lay.addWidget(self.lbl_vaka_investigator)

        right_lay.addWidget(self.case_info_box)

        # Environmental & Standard Badges
        env_title = QLabel("Adli Standart Uyumluluğu")
        env_title.setObjectName("sectionTitle")
        right_lay.addWidget(env_title)

        standards = [
            ("ISO/IEC 27037", "Dijital Delil Muhafaza Standardı", "verified"),
            ("NIST SP 800-86", "Windows Sistem Artefakt Analizi", "verified"),
            ("SWGDE 18-F-001", "Edinim & Raporlama Doğruluğu", "verified"),
            ("UNODC E4J M6", "Muhafaza Zinciri & Uçuculuk İlkesi", "verified"),
            ("SQLite WAL + Sync", "Elektrik Kesintisi & Çökme Koruması", "verified"),
        ]

        for std_name, std_desc, var in standards:
            s_row = QHBoxLayout()
            s_lbl = QLabel(f"• {std_name}: {std_desc}")
            s_lbl.setObjectName("mutedLabel")
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

    def _create_kpi_card(
        self,
        title: str,
        main_val: str,
        sub_val: str,
        icon_key: str,
        card_object_name: str = "surfaceCard",
        icon_color: str = "#60A5FA",
        icon_bg: str = "rgba(59, 130, 246, 0.14)",
        right_widget: QWidget = None,
    ) -> QFrame:
        card = QFrame()
        card.setObjectName(card_object_name)
        card.setFixedHeight(94)

        layout = QHBoxLayout(card)
        layout.setContentsMargins(14, 10, 14, 10)
        layout.setSpacing(12)

        icon_box = QLabel()
        icon_box.setFixedSize(40, 40)
        icon_box.setAlignment(Qt.AlignCenter)
        icon_box.setPixmap(render_svg_icon(icon_key, icon_color, 20).pixmap(20, 20))
        icon_box.setStyleSheet(
            f"background-color: {icon_bg}; border-radius: 9px;"
        )
        layout.addWidget(icon_box)

        text_lay = QVBoxLayout()
        text_lay.setSpacing(2)

        t_lbl = QLabel(title.upper())
        t_lbl.setObjectName("mutedLabel")
        t_lbl.setStyleSheet("font-size: 10px; font-weight: 700; letter-spacing: 0.6px; background: transparent;")
        text_lay.addWidget(t_lbl)

        v_lbl = QLabel(main_val)
        v_lbl.setObjectName("cardVal")
        text_lay.addWidget(v_lbl)

        s_lbl = QLabel(sub_val)
        s_lbl.setObjectName("cardSub")
        text_lay.addWidget(s_lbl)

        layout.addLayout(text_lay, 1)
        if right_widget is not None:
            layout.addWidget(right_widget)
        return card

    def refresh_data(self):
        """Reload database records and compute live forensic metrics (zero hardcoded KPIs)."""
        with self.Session() as s:
            all_cases = s.query(Case).all()
            active_cases = sum(1 for c in all_cases if c.status in ("open", "in_progress"))
            closed_cases = len(all_cases) - active_cases

            evds = s.query(Evidence).all()
            evd_count = len(evds)
            total_cap_gb = sum((e.capacity_bytes or 0) for e in evds) / (1024 ** 3)
            verified_evds = sum(1 for e in evds if e.status == "verified")
            mismatch_evds = sum(1 for e in evds if e.status == "hash_mismatch")

            usb_count = s.query(UsbDeviceRecord).count()
            susp_count = s.query(UsbDeviceRecord).filter(UsbDeviceRecord.is_suspicious == True).count()
            art_count = s.query(ForensicArtifact).count()

            audit_chk = verify_audit_chain(s)

            # Update ALL 4 KPI Cards dynamically from DB
            self.card_cases.findChild(QLabel, "cardVal").setText(f"{active_cases} Aktif Vaka")
            self.card_cases.findChild(QLabel, "cardSub").setText(f"{closed_cases} Kapanan / Arşiv")

            self.card_evidence.findChild(QLabel, "cardVal").setText(f"{evd_count} Adli Delil")
            self.card_evidence.findChild(QLabel, "cardSub").setText(f"{total_cap_gb:.1f} GB Toplam Kapasite")

            self.card_artifacts.findChild(QLabel, "cardVal").setText(f"{usb_count} USB | {art_count} Artefakt")
            self.card_artifacts.findChild(QLabel, "cardSub").setText(f"{susp_count} Şüpheli USB İşaretli")

            pct = int((verified_evds * 100) / evd_count) if evd_count else 0
            chain_txt = "Zincir Sağlam" if audit_chk["intact"] else "Zincir Bozuk!"
            self.card_integrity.findChild(QLabel, "cardVal").setText(f"%{pct} Doğrulandı")
            self.card_integrity.findChild(QLabel, "cardSub").setText(
                f"{verified_evds}/{evd_count} Delil ({mismatch_evds} Uyuşmaz) | {chain_txt}"
            )
            gauge_col = "#4ADE80" if (audit_chk["intact"] and mismatch_evds == 0) else "#F87171"
            self.integrity_gauge.set_value(pct, gauge_col)

            # Update Audit Log Table & Activity Spline Chart from live DB rows
            logs = s.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(100).all()
            records = []
            buckets = {}
            for log in logs:
                if log.timestamp:
                    b_key = log.timestamp.strftime("%m-%d %H:00")
                    buckets[b_key] = buckets.get(b_key, 0) + 1
                if len(records) < 50:
                    records.append({
                        "Zaman (UTC)": log.timestamp.strftime("%Y-%m-%d %H:%M:%S") if log.timestamp else "-",
                        "İşlem Türü": log.action,
                        "Sorumlu Uzman": log.investigator,
                        "Açıklama": log.details,
                        "Bütünlük Hash": (log.verification_hash[:16] + "...") if log.verification_hash else "Zincirsiz"
                    })
            self.activity_chart.set_series(
                sorted(buckets.items())[-12:],
                accent_color="#38BDF8",
                empty_text="Adli denetim aktivite kaydı yok",
            )
            self.table_audit.set_records(records)

    def _open_ingest_dialog(self):
        dlg = QDialog(self)
        dlg.setWindowTitle("Otomatik Çoklu-Modül Analiz Kuyruğu (Ingest Orchestrator)")
        dlg.setMinimumSize(620, 400)
        lay = QVBoxLayout(dlg)

        info = QLabel("Kayıtlı eklentiler üzerinden dosya seçip arka plan iş kuyruğunda analiz edin:")
        lay.addWidget(info)

        out_log = QTextEdit()
        out_log.setReadOnly(True)
        out_log.setStyleSheet("font-family: Consolas; font-size: 11px;")
        orch = AnalysisOrchestrator()
        plugins_txt = "\n".join(f"• {p.plugin_id}: {p.name} v{p.version} {p.extensions}" for p in orch.registry.list_plugins())
        out_log.setPlainText(f"YÜKLÜ ANALİZ EKLENTİLERİ:\n{plugins_txt}\n\nHazır.")
        lay.addWidget(out_log, 1)

        btn_row = QHBoxLayout()
        add_btn = QPushButton(" Dosya Seç & Kuyruğa Çalıştır")
        add_btn.setObjectName("primaryBtn")
        add_btn.setIcon(render_svg_icon("evidence", "#FFFFFF", 15))
        exp_uco = QPushButton(" CASE/UCO JSON-LD Dışa Aktar")
        exp_uco.setIcon(render_svg_icon("report", "#CBD5E1", 15))
        btn_row.addWidget(add_btn)
        btn_row.addWidget(exp_uco)
        btn_row.addStretch()
        lay.addLayout(btn_row)

        def run_ingest():
            files, _ = QFileDialog.getOpenFileNames(dlg, "Analiz Edilecek Delil / Artefakt Dosyalarını Seç")
            if not files:
                return
            for fp in files:
                job = orch.submit_job(case_id=1, source_path=fp)
                out_log.append(f"[QUEUED] {job.plugin_id} -> {fp}")
            add_btn.setEnabled(False)
            worker = FunctionWorker(orch.run_pending_jobs, parent=dlg)
            dlg._ingest_worker = worker

            def done(jobs):
                add_btn.setEnabled(True)
                for j in jobs:
                    out_log.append(f"[{j.status.value}] {j.plugin_id}: {j.findings_count} bulgu ({j.elapsed_sec}s)" + (f" | Hata: {j.error}" if j.error else ""))
                self.refresh_data()

            worker.finished_result.connect(done)
            worker.start()

        def export_uco():
            fp, _ = QFileDialog.getSaveFileName(dlg, "CASE/UCO JSON-LD Kaydet", "case_uco_bundle.json", "JSON (*.json)")
            if fp:
                orch.export_case_uco_jsonld(1, fp)
                out_log.append(f"[EXPORT] CASE/UCO JSON-LD yazıldı -> {fp}")

        add_btn.clicked.connect(run_ingest)
        exp_uco.clicked.connect(export_uco)
        dlg.exec()

    def set_active_case(self, case_id: int):
        """Update active case card from selected case ID."""
        with self.Session() as s:
            c = s.query(Case).filter(Case.id == case_id).first()
            if c:
                self.lbl_vaka_no.setText(f"Vaka No: {c.case_number}")
                self.lbl_vaka_title.setText(f"Konu: {c.title}")
                self.lbl_vaka_investigator.setText(f"Uzman: {c.investigator or '-'} ({c.organization or 'Adli Birim'})")

    def set_theme(self, theme_name: str):
        if hasattr(self, "hero_banner"):
            self.hero_banner.set_theme(theme_name)

    def _goto_page(self, index: int):
        window = self.window()
        if hasattr(window, "sidebar"):
            window.sidebar.select_page(index)
