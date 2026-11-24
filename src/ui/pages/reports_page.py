"""Forensic Report Generator Page with live HTML preview and PDF/HTML export."""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QCheckBox, QTextEdit, QTextBrowser, QSplitter,
    QFileDialog, QMessageBox
)
from PySide6.QtCore import Qt

from src.case_engine.case_service import CaseService
from src.report_engine.report_service import ReportService
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.status_indicator import StatusBadge


class ReportsPage(QWidget):
    """Auditable forensic report builder (HTML & PDF)."""

    def __init__(self, db_path: str = "data/forensics.db", parent=None):
        super().__init__(parent)
        self.db_path = db_path
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
        for chk in (self.chk_evd, self.chk_cust, self.chk_usb, self.chk_tl):
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
        html_btn = QPushButton("🌐 HTML Kaydet")
        html_btn.clicked.connect(self._export_html)
        btn_row.addWidget(html_btn)

        pdf_btn = QPushButton("📑 PDF Kaydet")
        pdf_btn.setObjectName("primaryBtn")
        pdf_btn.clicked.connect(self._export_pdf)
        btn_row.addWidget(pdf_btn)
        c_lay.addLayout(btn_row)
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
