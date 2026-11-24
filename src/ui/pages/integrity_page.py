"""Integrity & Chain of Custody Page with non-blocking QThread hash worker."""

from typing import List, Dict, Any, Optional
import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QSplitter, QTabWidget, QTextEdit, QLineEdit, QDialog,
    QFormLayout, QMessageBox, QFileDialog, QProgressBar, QApplication
)
from PySide6.QtCore import Qt, QThread, Signal

from src.integrity_engine.integrity_service import IntegrityService
from src.evidence_engine.evidence_service import EvidenceService
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.search_field import ForensicSearchField
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.status_indicator import StatusBadge


class HashWorker(QThread):
    """Background worker computing SHA-256 and SHA-512 without blocking the UI thread."""
    progress = Signal(int)
    finished_result = Signal(dict)
    failed = Signal(str)

    def __init__(self, file_path: str, parent=None):
        super().__init__(parent)
        self.file_path = file_path
        self._cancelled = False

    def cancel(self):
        self._cancelled = True

    def run(self):
        try:
            res = IntegrityService.compute_dual_hashes(
                self.file_path,
                progress_callback=self.progress.emit,
                cancel_check=lambda: self._cancelled,
            )
            self.finished_result.emit(res)
        except Exception as e:
            self.failed.emit(str(e))


class IntegrityPage(QWidget):
    """Cryptographic integrity verification and Chain of Custody tracking."""

    def __init__(self, db_path: str = "data/forensics.db", parent=None):
        super().__init__(parent)
        self.svc = IntegrityService(db_path=db_path)
        self.evd_svc = EvidenceService(db_path=db_path)
        self._worker: Optional[HashWorker] = None
        self._custody_records: List[Dict[str, Any]] = []
        self._last_computed: Optional[Dict[str, Any]] = None

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(14)

        # 1. Breadcrumb Header
        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Bütünlük & Muhafaza Zinciri (Chain of Custody)"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()

        self.custody_count_badge = StatusBadge("0 Muhafaza Kaydı", "verified")
        header_bar.addWidget(self.custody_count_badge)
        main_layout.addLayout(header_bar)

        # 2. Main Tab Widget
        self.tabs = QTabWidget()
        self.tabs.addTab(self._build_hash_tab(), "🔐 Kriptografik Hash & Doğrulama")
        self.tabs.addTab(self._build_custody_tab(), "📋 Muhafaza Zinciri (Chain of Custody)")
        main_layout.addWidget(self.tabs, 1)

        self.refresh_records()

    def _build_hash_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(14)

        # Forensic Note Banner
        note_frame = QFrame()
        note_frame.setObjectName("warnBanner")
        nf_lay = QHBoxLayout(note_frame)
        nf_lay.setContentsMargins(12, 8, 12, 8)
        note_lbl = QLabel(
            "⚠️ Adli İlke (NIST SP 800-86 & UNODC M6): Hash doğrulaması tek başına edinim güvenilirliğini kanıtlamaz. "
            "Edinim yöntemi, yazma engelleyici donanım ve erişim amacı Muhafaza Zinciri sekmesinde kaydedilmelidir."
        )
        note_lbl.setWordWrap(True)
        note_lbl.setObjectName("warnBannerText")
        nf_lay.addWidget(note_lbl)
        lay.addWidget(note_frame)

        # File Picker Card
        card = QFrame()
        card.setObjectName("surfaceCard")
        c_lay = QVBoxLayout(card)
        c_lay.setContentsMargins(16, 16, 16, 16)
        c_lay.setSpacing(10)

        c_title = QLabel("Dosya / Disk İmajı SHA-256 & SHA-512 Hesaplama (Salt Okunur)")
        c_title.setObjectName("sectionTitle")
        c_lay.addWidget(c_title)

        file_row = QHBoxLayout()
        self.path_input = QLineEdit()
        self.path_input.setPlaceholderText("Doğrulanacak adli imaj veya dosya yolunu seçin...")
        file_row.addWidget(self.path_input, 1)

        browse_btn = QPushButton("📁 Dosya Seç")
        browse_btn.clicked.connect(self._choose_file)
        file_row.addWidget(browse_btn)

        self.calc_btn = QPushButton("⚡ Hash Hesapla")
        self.calc_btn.setObjectName("primaryBtn")
        self.calc_btn.clicked.connect(self._start_hash_worker)
        file_row.addWidget(self.calc_btn)

        self.cancel_btn = QPushButton("İptal")
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_hash_worker)
        file_row.addWidget(self.cancel_btn)
        c_lay.addLayout(file_row)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(14)
        c_lay.addWidget(self.progress_bar)

        self.file_meta_lbl = QLabel("Boyut: - | Durum: Dosya seçilmedi")
        self.file_meta_lbl.setObjectName("monoLabel")
        c_lay.addWidget(self.file_meta_lbl)

        # SHA-256 Output
        sha256_row = QHBoxLayout()
        sha256_row.addWidget(QLabel("SHA-256:"))
        self.sha256_out = QLineEdit()
        self.sha256_out.setReadOnly(True)
        self.sha256_out.setStyleSheet("font-family: Consolas; font-size: 12px;")
        sha256_row.addWidget(self.sha256_out, 1)
        cp1 = QPushButton("Kopyala")
        cp1.clicked.connect(lambda: QApplication.clipboard().setText(self.sha256_out.text()))
        sha256_row.addWidget(cp1)
        c_lay.addLayout(sha256_row)

        # SHA-512 Output
        sha512_row = QHBoxLayout()
        sha512_row.addWidget(QLabel("SHA-512:"))
        self.sha512_out = QLineEdit()
        self.sha512_out.setReadOnly(True)
        self.sha512_out.setStyleSheet("font-family: Consolas; font-size: 11px;")
        sha512_row.addWidget(self.sha512_out, 1)
        cp2 = QPushButton("Kopyala")
        cp2.clicked.connect(lambda: QApplication.clipboard().setText(self.sha512_out.text()))
        sha512_row.addWidget(cp2)
        c_lay.addLayout(sha512_row)

        lay.addWidget(card)

        # Verification Card
        vcard = QFrame()
        vcard.setObjectName("surfaceCard")
        v_lay = QVBoxLayout(vcard)
        v_lay.setContentsMargins(16, 16, 16, 16)
        v_lay.setSpacing(10)

        v_title = QLabel("Beklenen Hash Karşılaştırma & Delil Kaydına İşleme")
        v_title.setObjectName("sectionTitle")
        v_lay.addWidget(v_title)

        comp_row = QHBoxLayout()
        self.expected_input = QLineEdit()
        self.expected_input.setPlaceholderText("Referans SHA-256 (64 karakter) veya SHA-512 (128 karakter) değerini yapıştırın...")
        self.expected_input.setStyleSheet("font-family: Consolas; font-size: 12px;")
        comp_row.addWidget(self.expected_input, 1)

        verify_btn = QPushButton("✓ Karşılaştır & Doğrula")
        verify_btn.setObjectName("primaryBtn")
        verify_btn.clicked.connect(self._compare_hashes)
        comp_row.addWidget(verify_btn)

        self.verify_result_badge = StatusBadge("Bekleniyor", "neutral")
        comp_row.addWidget(self.verify_result_badge)
        v_lay.addLayout(comp_row)

        # Link to evidence
        link_row = QHBoxLayout()
        link_row.addWidget(QLabel("Doğrulamayı Delile Kaydet:"))
        self.link_evidence_combo = QComboBox()
        self.link_evidence_combo.setMinimumWidth(260)
        link_row.addWidget(self.link_evidence_combo)

        save_custody_btn = QPushButton("📋 Muhafaza Zincirine Doğrulama Ekle")
        save_custody_btn.clicked.connect(self._record_verification_to_custody)
        link_row.addWidget(save_custody_btn)
        link_row.addStretch()
        v_lay.addLayout(link_row)

        lay.addWidget(vcard)
        lay.addStretch()
        return w

    def _build_custody_tab(self) -> QWidget:
        w = QWidget()
        lay = QVBoxLayout(w)
        lay.setContentsMargins(16, 16, 16, 16)
        lay.setSpacing(12)

        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)

        self.custody_search = ForensicSearchField("Delil No, Teslim Eden, Alan veya Hash Ara...")
        self.custody_search.searchChanged.connect(self._apply_custody_filters)
        toolbar.addWidget(self.custody_search, 2)

        self.evd_filter = QComboBox()
        self.evd_filter.setFixedWidth(220)
        self.evd_filter.currentIndexChanged.connect(self._apply_custody_filters)
        toolbar.addWidget(self.evd_filter)

        add_entry_btn = QPushButton("➕ Teslim / İşlem Kaydı Ekle")
        add_entry_btn.setObjectName("primaryBtn")
        add_entry_btn.clicked.connect(self._open_add_custody_dialog)
        toolbar.addWidget(add_entry_btn)

        export_btn = QPushButton("CSV Dışa Aktar")
        export_btn.clicked.connect(lambda: self.custody_table.export_to_csv())
        toolbar.addWidget(export_btn)
        lay.addLayout(toolbar)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        headers = [
            "Doğrulama", "Zaman (UTC)", "Delil No", "İşlem Türü",
            "Teslim Eden", "Teslim Alan", "Yazma Engelleyici / Yöntem", "Hash (Özet)"
        ]
        self.custody_table = ForensicDataTable(headers, self)
        self.custody_table.rowSelected.connect(self._on_custody_selected)
        splitter.addWidget(self.custody_table)

        self.custody_detail = QTextEdit()
        self.custody_detail.setReadOnly(True)
        self.custody_detail.setFixedWidth(340)
        self.custody_detail.setStyleSheet("font-family: Consolas; font-size: 11px;")
        splitter.addWidget(self.custody_detail)

        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)
        lay.addWidget(splitter, 1)
        return w

    def refresh_records(self):
        # Populate Evidence combos
        evds = self.evd_svc.list_evidence()
        self.link_evidence_combo.clear()
        self.evd_filter.blockSignals(True)
        self.evd_filter.clear()
        self.evd_filter.addItem("Tüm Deliller", None)
        for e in evds:
            lbl = f"{e.evidence_number} - {e.brand} {e.model}".strip()
            self.link_evidence_combo.addItem(lbl, (e.case_id, e.id))
            self.evd_filter.addItem(lbl, e.id)
        self.evd_filter.blockSignals(False)

        rows = self.svc.list_custody_records()
        self._custody_records = []
        for item in rows:
            entry = item["entry"]
            evd_num = item["evidence_number"]
            sha_short = f"{entry.sha256_at_event[:12]}..." if entry.sha256_at_event else "-"
            self._custody_records.append({
                "id": entry.id,
                "evidence_id": entry.evidence_id,
                "Doğrulama": entry.verification_status or "Doğrulandı",
                "Zaman (UTC)": entry.timestamp.strftime("%Y-%m-%d %H:%M:%S") if entry.timestamp else "-",
                "Delil No": evd_num,
                "İşlem Türü": entry.action_type,
                "Teslim Eden": entry.delivered_by or "-",
                "Teslim Alan": entry.received_by or "-",
                "Yazma Engelleyici / Yöntem": entry.write_blocker_info or entry.acquire_method or "-",
                "Hash (Özet)": sha_short,
                "location": entry.location or "-",
                "acquire_method": entry.acquire_method or "-",
                "sha256": entry.sha256_at_event or "-",
                "sha512": entry.sha512_at_event or "-",
                "notes": entry.notes or "-",
            })

        self.custody_count_badge.set_status(f"{len(self._custody_records)} Muhafaza Kaydı", "verified")
        self._apply_custody_filters()
        if self._custody_records:
            self._on_custody_selected(self._custody_records[0])

    def _apply_custody_filters(self):
        records = list(self._custody_records)
        eid = self.evd_filter.currentData()
        if eid is not None:
            records = [r for r in records if r["evidence_id"] == eid]

        q = self.custody_search.text().lower()
        if q:
            records = [r for r in records if any(q in str(v).lower() for v in r.values())]

        self.custody_table.set_records(records)

    def _on_custody_selected(self, rec: Dict[str, Any]):
        detail = (
            f"DELİL NO:    {rec['Delil No']}\n"
            f"ZAMAN (UTC): {rec['Zaman (UTC)']}\n"
            f"İŞLEM:       {rec['İşlem Türü']}\n"
            f"DURUM:       {rec['Doğrulama']}\n"
            f"KONUM:       {rec['location']}\n"
            f"TESLİM EDEN: {rec['Teslim Eden']}\n"
            f"TESLİM ALAN: {rec['Teslim Alan']}\n"
            f"EDİNİM:      {rec['acquire_method']}\n"
            f"DONANIM/WB:  {rec['Yazma Engelleyici / Yöntem']}\n\n"
            f"SHA-256:\n{rec['sha256']}\n\n"
            f"SHA-512:\n{rec['sha512']}\n\n"
            f"NOTLAR:\n{rec['notes']}"
        )
        self.custody_detail.setPlainText(detail)

    def _choose_file(self):
        fp, _ = QFileDialog.getOpenFileName(self, "Bütünlük Kontrolü İçin Dosya Seç")
        if fp:
            self.path_input.setText(fp)

    def _start_hash_worker(self):
        fp = self.path_input.text().strip()
        if not fp or not os.path.isfile(fp):
            QMessageBox.warning(self, "Geçersiz Dosya", "Lütfen mevcut bir dosya yolu seçin.")
            return

        self.calc_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.file_meta_lbl.setText("Hesaplanıyor (Salt Okunur)...")

        self._worker = HashWorker(fp, self)
        self._worker.progress.connect(self.progress_bar.setValue)
        self._worker.finished_result.connect(self._on_hash_finished)
        self._worker.failed.connect(self._on_hash_failed)
        self._worker.start()

    def _cancel_hash_worker(self):
        if self._worker and self._worker.isRunning():
            self._worker.cancel()

    def _on_hash_finished(self, res: Dict[str, Any]):
        self._last_computed = res
        self.calc_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        self.sha256_out.setText(res["sha256"])
        self.sha512_out.setText(res["sha512"])
        self.file_meta_lbl.setText(
            f"Dosya: {res['file_name']} | Boyut: {res['file_size']:,} bayt | Tamamlandı (UTC)"
        )
        if self.expected_input.text().strip():
            self._compare_hashes()

    def _on_hash_failed(self, err: str):
        self.calc_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.file_meta_lbl.setText(f"Hata: {err}")
        QMessageBox.warning(self, "Hash Hatası", err)

    def _compare_hashes(self):
        expected = self.expected_input.text().strip().lower()
        if not expected:
            QMessageBox.warning(self, "Eksik Değer", "Lütfen karşılaştırılacak beklenen hash değerini girin.")
            return

        s256 = self.sha256_out.text().strip().lower()
        s512 = self.sha512_out.text().strip().lower()
        if not s256 and self.path_input.text().strip() and os.path.isfile(self.path_input.text().strip()):
            res = IntegrityService.compute_dual_hashes(self.path_input.text().strip())
            self._on_hash_finished(res)
            s256 = res["sha256"].lower()
            s512 = res["sha512"].lower()

        if len(expected) == 64 and s256 == expected:
            self.verify_result_badge.set_status("EŞLEŞTİ (SHA-256)", "verified")
        elif len(expected) == 128 and s512 == expected:
            self.verify_result_badge.set_status("EŞLEŞTİ (SHA-512)", "verified")
        else:
            self.verify_result_badge.set_status("UYUŞMAZLIK!", "critical")

    def _record_verification_to_custody(self):
        data = self.link_evidence_combo.currentData()
        if not data:
            QMessageBox.warning(self, "Delil Seçilmedi", "Lütfen kayıtlı bir delil seçin.")
            return
        case_id, evd_id = data
        s256 = self.sha256_out.text().strip()
        s512 = self.sha512_out.text().strip()
        if not s256:
            QMessageBox.warning(self, "Hash Yok", "Önce dosya hash değerini hesaplayın.")
            return

        evd = self.evd_svc.get_evidence(evd_id)
        matched = True
        if evd and evd.sha256_hash:
            matched = (evd.sha256_hash.lower() == s256.lower())

        status = "Doğrulandı" if matched else "Uyuşmazlık"
        self.svc.add_custody_entry(
            case_id=case_id,
            evidence_id=evd_id,
            action_type="Bütünlük Doğrulandı" if matched else "Bütünlük Uyuşmazlığı Tespit Edildi",
            delivered_by="Çalışma Kopyası",
            received_by="Adli Bilişim Uzmanı",
            location="Bütünlük Doğrulama Modülü",
            acquire_method="Çift Katmanlı SHA-256 / SHA-512",
            write_blocker_info="Salt Okunur Dosya Okuma",
            sha256_at_event=s256,
            sha512_at_event=s512,
            verification_status=status,
            notes=f"Dosya yolu: {self.path_input.text().strip()}",
        )
        self.refresh_records()
        QMessageBox.information(self, "Kaydedildi", f"Muhafaza zincirine doğrulama kaydı eklendi ({status}).")

    def _open_add_custody_dialog(self):
        evds = self.evd_svc.list_evidence()
        if not evds:
            QMessageBox.warning(self, "Delil Yok", "Önce bir delil kaydı oluşturun.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Yeni Muhafaza Zinciri (Chain of Custody) Kaydı")
        dlg.setMinimumWidth(480)
        lay = QVBoxLayout(dlg)
        form = QFormLayout()

        cb_evd = QComboBox()
        for e in evds:
            cb_evd.addItem(f"{e.evidence_number} - {e.brand} {e.model}", (e.case_id, e.id))

        cb_action = QComboBox()
        cb_action.setEditable(True)
        cb_action.addItems(["Devredildi", "İncelemeye Çıktı", "Kasa İadesi", "Bütünlük Doğrulandı", "Arşivlendi"])

        delivered = QLineEdit()
        received = QLineEdit()
        purpose = QLineEdit("Adli İnceleme / Çalışma Kopyası Analizi")
        location = QLineEdit("Adli Bilişim Laboratuvarı")
        method = QLineEdit("Fiziksel Teslim / Çalışma Kopyası")
        wb_info = QLineEdit("Tableau T8u Hardware Write-Blocker (Doğrulandı)")
        cb_status = QComboBox()
        cb_status.addItems(["Doğrulandı", "Uyarı", "Uyuşmazlık"])
        notes = QTextEdit()
        notes.setFixedHeight(70)

        form.addRow("Delil *:", cb_evd)
        form.addRow("İşlem Türü *:", cb_action)
        form.addRow("Teslim Eden *:", delivered)
        form.addRow("Teslim Alan *:", received)
        form.addRow("Erişim Amacı (UNODC) *:", purpose)
        form.addRow("Konum:", location)
        form.addRow("Edinim / Erişim Yöntemi:", method)
        form.addRow("Yazma Engelleyici / Donanım:", wb_info)
        form.addRow("Doğrulama Durumu:", cb_status)
        form.addRow("Notlar:", notes)
        lay.addLayout(form)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("İptal")
        cancel_btn.clicked.connect(dlg.reject)
        save_btn = QPushButton("Kaydet")
        save_btn.setObjectName("primaryBtn")
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(save_btn)
        lay.addLayout(btn_row)

        def submit():
            if not delivered.text().strip() or not received.text().strip():
                QMessageBox.warning(dlg, "Eksik Bilgi", "Teslim eden ve teslim alan bilgileri zorunludur.")
                return
            cid, eid = cb_evd.currentData()
            combined_notes = f"[Erişim Amacı: {purpose.text().strip()}]\n{notes.toPlainText().strip()}".strip()
            self.svc.add_custody_entry(
                case_id=cid,
                evidence_id=eid,
                action_type=cb_action.currentText(),
                delivered_by=delivered.text(),
                received_by=received.text(),
                location=location.text(),
                acquire_method=method.text(),
                write_blocker_info=wb_info.text(),
                verification_status=cb_status.currentText(),
                notes=combined_notes,
            )
            dlg.accept()
            self.refresh_records()

        save_btn.clicked.connect(submit)
        dlg.exec()
