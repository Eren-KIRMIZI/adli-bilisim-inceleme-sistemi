"""Forensic Report Generator Page with live HTML preview and PDF/HTML export."""

import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QCheckBox, QTextEdit, QTextBrowser, QSplitter,
    QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt

from src.case_engine.case_service import CaseService
from src.report_engine.report_service import ReportService
from src.core.auth_service import AuthService
from src.core.signing_service import SigningService
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.status_indicator import StatusBadge


class ReportsPage(QWidget):
    """Auditable forensic report builder (HTML & PDF) with X.509 cryptographic signing."""

    def __init__(self, db_path: str = "data/forensics.db", cert_dir: str = "data/certs", parent=None):
        super().__init__(parent)
        self.db_path = db_path
        self.cert_dir = cert_dir
        self._active_user = "Adli Bilişim Uzmanı E. Kırmızı"
        self._active_role = "LeadInvestigator"
        self.case_svc = CaseService(db_path=db_path)
        self.report_svc = ReportService(db_path=db_path)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 18, 24, 18)
        main_layout.setSpacing(12)

        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Adli Rapor Oluşturucu"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()
        header_bar.addWidget(StatusBadge("Denetlenebilir HTML & PDF", "verified"))
        main_layout.addLayout(header_bar)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Left Configuration Panel
        cfg = QFrame()
        cfg.setObjectName("surfaceCard")
        cfg.setFixedWidth(380)
        c_lay = QVBoxLayout(cfg)
        c_lay.setContentsMargins(14, 14, 14, 14)
        c_lay.setSpacing(10)

        c_lay.addWidget(QLabel("Raporlanacak Vaka:"))
        self.case_combo = QComboBox()
        c_lay.addWidget(self.case_combo)

        c_lay.addWidget(QLabel("Rapora Dahil Edilecek Bölümler:"))
        self.chk_evd = QCheckBox("Delil Envanteri & Hash Değerleri")
        self.chk_evd.setChecked(True)
        self.chk_cust = QCheckBox("Muhafaza Zinciri (Chain of Custody)")
        self.chk_cust.setChecked(True)
        self.chk_usb = QCheckBox("USB Cihaz & Artefakt Bulguları")
        self.chk_usb.setChecked(True)
        self.chk_tl = QCheckBox("Olay Zaman Çizelgesi (UTC)")
        self.chk_tl.setChecked(True)
        self.chk_art = QCheckBox("Çoklu Modül Artefakt & IOC Bulguları")
        self.chk_art.setChecked(True)
        for chk in (self.chk_evd, self.chk_cust, self.chk_usb, self.chk_tl, self.chk_art):
            chk.toggled.connect(self.update_preview)
            c_lay.addWidget(chk)

        c_lay.addWidget(QLabel("Uzman Değerlendirme Notları:"))
        self.notes_edit = QTextEdit()
        self.notes_edit.setFixedHeight(85)
        self.notes_edit.setPlaceholderText("Boş bırakılırsa standart teknik değerlendirme özeti eklenir...")
        c_lay.addWidget(self.notes_edit)

        c_lay.addWidget(QLabel("Analiz Sınırlamaları:"))
        self.limits_edit = QTextEdit()
        self.limits_edit.setFixedHeight(75)
        self.limits_edit.setPlaceholderText("Boş bırakılırsa adli sınırlamalar ve yazma engelleyici notu eklenir...")
        c_lay.addWidget(self.limits_edit)

        preview_btn = QPushButton("🔄 Önizlemeyi Güncelle")
        preview_btn.clicked.connect(self.update_preview)
        c_lay.addWidget(preview_btn)

        btn_row = QHBoxLayout()
        html_btn = QPushButton(" HTML Kaydet")
        html_btn.clicked.connect(self._export_html)
        btn_row.addWidget(html_btn)

        pdf_btn = QPushButton(" PDF Kaydet")
        pdf_btn.setObjectName("primaryBtn")
        pdf_btn.clicked.connect(self._export_pdf)
        btn_row.addWidget(pdf_btn)
        c_lay.addLayout(btn_row)

        exp2_row = QHBoxLayout()
        stix_btn = QPushButton("STIX 2.1 IOC")
        stix_btn.clicked.connect(self._export_stix2)
        exp2_row.addWidget(stix_btn)

        csv_btn = QPushButton("CSV Zaman Çizelgesi")
        csv_btn.clicked.connect(self._export_csv_timeline)
        exp2_row.addWidget(csv_btn)
        c_lay.addLayout(exp2_row)

        # X.509 RSA-PSS Cryptographic Signing Section
        sig_title = QLabel("Kriptografik X.509 Rapor İmzalama (RSA-PSS)")
        sig_title.setObjectName("sectionTitle")
        c_lay.addWidget(sig_title)

        sig_row = QHBoxLayout()
        self.sign_btn = QPushButton(" X.509 İmzala")
        self.sign_btn.clicked.connect(self._sign_exported_report)
        sig_row.addWidget(self.sign_btn)

        verify_sig_btn = QPushButton(" İmza Doğrula")
        verify_sig_btn.clicked.connect(self._verify_report_signature)
        sig_row.addWidget(verify_sig_btn)
        c_lay.addLayout(sig_row)

        self.sig_status_badge = StatusBadge("X.509 İmza Modülü Hazır", "info")
        c_lay.addWidget(self.sig_status_badge)
        c_lay.addStretch()
        splitter.addWidget(cfg)

        # Right HTML Live Preview
        prev_card = QFrame()
        prev_card.setObjectName("surfaceCard")
        p_lay = QVBoxLayout(prev_card)
        p_lay.setContentsMargins(10, 10, 10, 10)
        p_lay.addWidget(QLabel("Canlı Adli Rapor Önizlemesi"))
        self.preview = QTextBrowser()
        self.preview.setStyleSheet("background: #FFFFFF; border: 1px solid #EAECF0; border-radius: 6px;")
        p_lay.addWidget(self.preview)
        splitter.addWidget(prev_card)

        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 7)
        main_layout.addWidget(splitter, 1)

        self.refresh_records()

    def refresh_records(self):
        self.case_combo.blockSignals(True)
        self.case_combo.clear()
        for c in self.case_svc.list_cases():
            self.case_combo.addItem(f"{c.case_number} - {c.title}", c.id)
        self.case_combo.blockSignals(False)
        self.update_preview()

    def _gather_kwargs(self):
        return {
            "case_id": self.case_combo.currentData(),
            "include_evidence": self.chk_evd.isChecked(),
            "include_custody": self.chk_cust.isChecked(),
            "include_usb": self.chk_usb.isChecked(),
            "include_timeline": self.chk_tl.isChecked(),
            "include_artifacts": self.chk_art.isChecked(),
            "expert_notes": self.notes_edit.toPlainText(),
            "limitations": self.limits_edit.toPlainText(),
        }

    def update_preview(self):
        try:
            html = self.report_svc.render_html(**self._gather_kwargs())
            self.preview.setHtml(html)
        except Exception as e:
            self.preview.setPlainText(f"Önizleme hatası: {e}")

    def _export_html(self):
        path, _ = QFileDialog.getSaveFileName(self, "HTML Rapor Kaydet", "adli_rapor.html", "HTML (*.html)")
        if not path:
            return
        self.report_svc.export_html(path, **self._gather_kwargs())
        QMessageBox.information(self, "HTML Rapor Hazır", f"Rapor kaydedildi:\n{path}")

    def _export_pdf(self):
        path, _ = QFileDialog.getSaveFileName(self, "PDF Rapor Kaydet", "adli_rapor.pdf", "PDF (*.pdf)")
        if not path:
            return
        self.report_svc.export_pdf(path, **self._gather_kwargs())
        QMessageBox.information(self, "PDF Rapor Hazır", f"PDF raporu oluşturuldu:\n{path}")

    def _export_stix2(self):
        from src.core.orchestrator import AnalysisOrchestrator
        cid = self.case_combo.currentData() or 1
        path, _ = QFileDialog.getSaveFileName(self, "STIX 2.1 IOC Paketi Kaydet", "outputs/adli_stix2.json", "STIX JSON (*.json)")
        if not path:
            return
        AnalysisOrchestrator(db_path=self.db_path).export_stix2_bundle(cid, path)
        QMessageBox.information(self, "STIX 2.1 Hazır", f"STIX 2.1 IOC paketi kaydedildi:\n{path}")

    def _export_csv_timeline(self):
        from src.core.orchestrator import AnalysisOrchestrator
        from src.timeline_engine.timeline_service import TimelineService
        cid = self.case_combo.currentData() or 1
        path, _ = QFileDialog.getSaveFileName(self, "CSV Zaman Çizelgesi Kaydet", "outputs/zaman_cizelgesi.csv", "CSV (*.csv)")
        if not path:
            return
        events = TimelineService(db_path=self.db_path).collect_case_timeline(case_id=cid)
        AnalysisOrchestrator.export_csv(events, path)
        QMessageBox.information(self, "CSV Hazır", f"Excel uyumlu UTF-8 BOM CSV kaydedildi:\n{path}")

    def set_operator(self, full_name: str, role: str) -> None:
        self._active_user = full_name
        self._active_role = role

    def populate_signature_status(self, label: str, variant: str = "verified") -> None:
        self.sig_status_badge.set_status(label, variant)

    def _sign_exported_report(self):
        if not AuthService.can_perform(self._active_role, "sign_report"):
            QMessageBox.warning(
                self,
                "RBAC Yetki Reddi",
                f"Aktif rol '{self._active_role}' kriptografik rapor imzalama yetkisine sahip değil (LeadInvestigator/Admin gerekir).",
            )
            return
        fp, _ = QFileDialog.getOpenFileName(
            self, "İmzalanacak PDF/HTML Raporu Seç", "outputs", "Raporlar (*.pdf *.html);;Tüm Dosyalar (*.*)"
        )
        if not fp:
            return
        sig_doc = SigningService.sign_file(fp, signer_name=self._active_user, signer_role=self._active_role, cert_dir=self.cert_dir)
        fp_short = sig_doc["cert_fingerprint_sha256"][:16]
        self.sig_status_badge.set_status(f"X.509 İmzalandı ({fp_short}...)", "verified")
        QMessageBox.information(
            self,
            "X.509 İmza Oluşturuldu",
            f"Rapor RSA-PSS-SHA256 ile imzalandı.\nİmza Paketi:\n{sig_doc['signature_path']}\nSertifika SHA-256: {sig_doc['cert_fingerprint_sha256']}",
        )

    def _verify_report_signature(self):
        fp, _ = QFileDialog.getOpenFileName(
            self, "Doğrulanacak Rapor Dosyasını Seç", "outputs", "Raporlar (*.pdf *.html);;Tüm Dosyalar (*.*)"
        )
        if not fp:
            return
        sp = fp + ".sig.json"
        if not os.path.isfile(sp):
            sp, _ = QFileDialog.getOpenFileName(self, "İmza Dosyasını Seç (.sig.json)", os.path.dirname(fp), "Signature (*.sig.json)")
        if not sp or not os.path.isfile(sp):
            return
        res = SigningService.verify_signature(fp, sp)
        if res["valid"]:
            self.sig_status_badge.set_status("İmza Geçerli (Kurcalanmamış)", "verified")
            QMessageBox.information(
                self,
                "Kriptografik Doğrulama Başarılı",
                f"X.509 İmza Geçerli!\nİmzalayan: {res['signer_name']} ({res['signer_role']})\nTarih: {res['signed_at_utc']}\nSHA-256: {res['actual_sha256']}",
            )
        else:
            self.sig_status_badge.set_status("İmza Geçersiz / Değiştirilmiş!", "critical")
            QMessageBox.critical(
                self,
                "Kriptografik Uyuşmazlık",
                f"UYARI: Rapor dosyası imzalandıktan sonra değiştirilmiş veya imza geçersiz!\nHash Eşleşti: {res['hash_matched']}\nKripto Geçerli: {res['signature_crypto_valid']}",
            )
