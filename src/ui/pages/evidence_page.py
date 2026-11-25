"""Evidence Manager Page with intake workflow, hardware metadata, and hash inspector."""

from typing import List, Dict, Any, Optional
import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QSplitter, QTabWidget, QTextEdit, QLineEdit, QDialog,
    QFormLayout, QMessageBox, QCheckBox, QFileDialog, QApplication
)
from PySide6.QtCore import Qt, Signal

from src.evidence_engine.evidence_service import EvidenceService
from src.case_engine.case_service import CaseService
from src.integrity_engine.integrity_service import IntegrityService
from src.ui.workers import HashWorker, FunctionWorker
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.search_field import ForensicSearchField
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.status_indicator import StatusBadge


class EvidencePage(QWidget):
    """Digital Evidence inventory and acquisition metadata management workspace."""

    activeEvidenceSelected = Signal(int, str)  # evidence_id, display_label

    def __init__(self, db_path: str = "data/forensics.db", parent=None):
        super().__init__(parent)
        self.svc = EvidenceService(db_path=db_path)
        self.case_svc = CaseService(db_path=db_path)
        self.integrity_svc = IntegrityService(db_path=db_path)

        self._all_records: List[Dict[str, Any]] = []
        self._selected_evidence_id: Optional[int] = None
        self._active_case_id: Optional[int] = None

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(14)

        # 1. Breadcrumb Header
        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Delil Yönetimi (Evidence)"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()

        self.count_badge = StatusBadge("0 Delil", "info")
        header_bar.addWidget(self.count_badge)
        main_layout.addLayout(header_bar)

        # 2. Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)

        self.search_field = ForensicSearchField("Delil No, Marka, Model, Seri No veya SHA-256 Ara...")
        self.search_field.searchChanged.connect(self._apply_filters)
        toolbar.addWidget(self.search_field, 2)

        self.case_filter = QComboBox()
        self.case_filter.setFixedWidth(180)
        self.case_filter.currentIndexChanged.connect(self._apply_filters)
        toolbar.addWidget(self.case_filter)

        self.type_filter = QComboBox()
        self.type_filter.addItems(["Tüm Türler", "USB Flash Bellek", "Disk İmajı", "NVMe / SSD", "RAM Dökümü", "Diğer"])
        self.type_filter.setFixedWidth(160)
        self.type_filter.currentIndexChanged.connect(self._apply_filters)
        toolbar.addWidget(self.type_filter)

        self.set_active_btn = QPushButton("✓ Aktif Delil Seç")
        self.set_active_btn.clicked.connect(self._activate_selected_evidence)
        toolbar.addWidget(self.set_active_btn)

        new_btn = QPushButton("📥 Yeni Delil Kabul Et")
        new_btn.setObjectName("primaryBtn")
        new_btn.clicked.connect(self._open_intake_dialog)
        toolbar.addWidget(new_btn)

        main_layout.addLayout(toolbar)

        # 3. Main Splitter: Evidence Table + Inspector
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        table_card = QFrame()
        table_card.setObjectName("surfaceCard")
        t_lay = QVBoxLayout(table_card)
        t_lay.setContentsMargins(12, 12, 12, 12)
        t_lay.setSpacing(8)

        tbl_title = QLabel("Kayıtlı Dijital Delil Envanteri")
        tbl_title.setObjectName("sectionTitle")
        t_lay.addWidget(tbl_title)

        headers = [
            "Durum", "Delil No", "Vaka No", "Tür", "Marka / Model",
            "Seri Numarası", "Yazma Engelleyici", "SHA-256 (Özet)", "Kabul Tarihi"
        ]
        self.table = ForensicDataTable(headers, self)
        self.table.rowSelected.connect(self._on_evidence_selected)
        t_lay.addWidget(self.table)
        splitter.addWidget(table_card)

        # Right Inspector Panel
        self.inspector = QFrame()
        self.inspector.setObjectName("surfaceCard")
        self.inspector.setFixedWidth(380)
        ins_lay = QVBoxLayout(self.inspector)
        ins_lay.setContentsMargins(14, 14, 14, 14)
        ins_lay.setSpacing(10)

        ins_head = QHBoxLayout()
        self.ins_title = QLabel("Delil Seçilmedi")
        self.ins_title.setObjectName("sectionTitle")
        ins_head.addWidget(self.ins_title)
        ins_head.addStretch()
        self.ins_badge = StatusBadge("-", "neutral")
        ins_head.addWidget(self.ins_badge)
        ins_lay.addLayout(ins_head)

        self.tabs = QTabWidget()

        # Tab 1: Envanter & Donanım
        self.tab_hw = QTextEdit()
        self.tab_hw.setReadOnly(True)
        self.tabs.addTab(self.tab_hw, "Envanter & Donanım")

        # Tab 2: Hash & Bütünlük
        tab_hash = QWidget()
        th_lay = QVBoxLayout(tab_hash)
        th_lay.setContentsMargins(8, 10, 8, 8)
        th_lay.setSpacing(8)

        th_lay.addWidget(QLabel("SHA-256 Özeti:"))
        self.txt_sha256 = QLineEdit()
        self.txt_sha256.setReadOnly(True)
        self.txt_sha256.setStyleSheet("font-family: Consolas; font-size: 11px;")
        th_lay.addWidget(self.txt_sha256)

        cp256 = QPushButton("SHA-256 Kopyala")
        cp256.clicked.connect(lambda: QApplication.clipboard().setText(self.txt_sha256.text()))
        th_lay.addWidget(cp256)

        th_lay.addWidget(QLabel("SHA-512 Özeti:"))
        self.txt_sha512 = QTextEdit()
        self.txt_sha512.setReadOnly(True)
        self.txt_sha512.setFixedHeight(75)
        self.txt_sha512.setStyleSheet("font-family: Consolas; font-size: 11px;")
        th_lay.addWidget(self.txt_sha512)

        self.verify_disk_btn = QPushButton("🔐 Diskteki Dosyayı Doğrula")
        self.verify_disk_btn.setObjectName("primaryBtn")
        self.verify_disk_btn.clicked.connect(self._verify_selected_file)
        th_lay.addWidget(self.verify_disk_btn)
        th_lay.addStretch()
        self.tabs.addTab(tab_hash, "Hash & Bütünlük")

        # Tab 3: Muhafaza Geçmişi
        self.custody_table = ForensicDataTable(["Doğrulama", "Zaman (UTC)", "İşlem", "Teslim Alan"], self)
        self.tabs.addTab(self.custody_table, "Muhafaza Geçmişi")

        ins_lay.addWidget(self.tabs)
        splitter.addWidget(self.inspector)

        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)
        main_layout.addWidget(splitter, 1)

        self.refresh_records()

    def set_case_context(self, case_id: Optional[int]):
        self._active_case_id = case_id
        self.refresh_records()

    def refresh_records(self):
        # Populate case filter dropdown without triggering redundant reloads
        self.case_filter.blockSignals(True)
        self.case_filter.clear()
        self.case_filter.addItem("Tüm Vakalar", None)
        for c in self.case_svc.list_cases():
            self.case_filter.addItem(f"{c.case_number} - {c.title[:18]}", c.id)
        if self._active_case_id:
            idx = self.case_filter.findData(self._active_case_id)
            if idx >= 0:
                self.case_filter.setCurrentIndex(idx)
        self.case_filter.blockSignals(False)

        rows = self.svc.list_evidence_with_case()
        self._all_records = []
        for row in rows:
            e = row["evidence"]
            case_num = row["case_number"]
            status_tr = "Doğrulandı" if e.status == "verified" else ("İnceleniyor" if e.status == "analyzing" else e.status)
            cap_str = f"{e.capacity_bytes / (1024**3):.1f} GB" if e.capacity_bytes else "-"
            sha_short = f"{e.sha256_hash[:12]}..." if e.sha256_hash else "Hesaplanmadı"

            self._all_records.append({
                "id": e.id,
                "case_id": e.case_id,
                "Durum": status_tr,
                "Delil No": e.evidence_number,
                "Vaka No": case_num,
                "Tür": e.device_type or "-",
                "Marka / Model": f"{e.brand or ''} {e.model or ''}".strip() or "-",
                "Seri Numarası": e.serial or "-",
                "Yazma Engelleyici": "Evet (Korumalı)" if e.write_blocker_used else "Belirtilmedi",
                "SHA-256 (Özet)": sha_short,
                "Kabul Tarihi": e.acquire_date.strftime("%Y-%m-%d %H:%M") if e.acquire_date else "-",
                "full_sha256": e.sha256_hash or "",
                "full_sha512": e.sha512_hash or "",
                "custodian": e.custodian or "-",
                "acquire_tool": e.acquire_tool or "-",
                "capacity": cap_str,
                "file_path": e.file_path or "-",
                "notes": e.notes or "-",
            })

        self.count_badge.set_status(f"{len(self._all_records)} Delil", "info")
        self._apply_filters()
        if self._all_records:
            self._load_inspector(self._all_records[0])

    def _apply_filters(self):
        records = list(self._all_records)
        cid = self.case_filter.currentData()
        if cid is not None:
            records = [r for r in records if r["case_id"] == cid]

        typ = self.type_filter.currentText()
        if typ != "Tüm Türler":
            records = [r for r in records if typ.lower() in r["Tür"].lower()]

        q = self.search_field.text().lower()
        if q:
            records = [r for r in records if any(q in str(v).lower() for v in r.values())]

        self.table.set_records(records)

    def _on_evidence_selected(self, record: Dict[str, Any]):
        self._load_inspector(record)

    def _load_inspector(self, rec: Dict[str, Any]):
        self._selected_evidence_id = rec["id"]
        self.ins_title.setText(rec["Delil No"])
        variant = "verified" if "doğrulandı" in rec["Durum"].lower() else "info"
        self.ins_badge.set_status(rec["Durum"], variant)

        hw_text = (
            f"Delil No:         {rec['Delil No']}\n"
            f"Bağlı Vaka:       {rec['Vaka No']}\n"
            f"Tür:              {rec['Tür']}\n"
            f"Marka / Model:    {rec['Marka / Model']}\n"
            f"Seri Numarası:    {rec['Seri Numarası']}\n"
            f"Kapasite:         {rec['capacity']}\n"
            f"Teslim Alan:      {rec['custodian']}\n"
            f"Edinim Donanımı:  {rec['acquire_tool']}\n"
            f"Yazma Engelleyici:{rec['Yazma Engelleyici']}\n"
            f"Dosya Yolu:       {rec['file_path']}\n\n"
            f"Notlar:\n{rec['notes']}"
        )
        self.tab_hw.setPlainText(hw_text)
        self.txt_sha256.setText(rec["full_sha256"] or "Kayıtlı değil")
        self.txt_sha512.setPlainText(rec["full_sha512"] or "Kayıtlı değil")

        cust_records = self.integrity_svc.list_custody_records(evidence_id=rec["id"])
        c_rows = []
        for item in cust_records:
            entry = item["entry"]
            c_rows.append({
                "Doğrulama": entry.verification_status,
                "Zaman (UTC)": entry.timestamp.strftime("%Y-%m-%d %H:%M") if entry.timestamp else "-",
                "İşlem": entry.action_type,
                "Teslim Alan": entry.received_by or "-",
            })
        self.custody_table.set_records(c_rows)

    def _verify_selected_file(self):
        if not self._selected_evidence_id:
            return
        evd = self.svc.get_evidence(self._selected_evidence_id)
        if not evd or not evd.file_path or not os.path.isfile(evd.file_path):
            QMessageBox.information(
                self,
                "Dosya Yolu Eksik",
                "Bu delil için disk üzerinde erişilebilir bir imaj dosyası yolu kayıtlı değil. Doğrulamak için Bütünlük & Hash modülünden dosya seçebilirsiniz.",
            )
            return
        self.verify_disk_btn.setEnabled(False)
        self.verify_disk_btn.setText("⏳ Doğrulanıyor (Arka Plan)...")
        worker = FunctionWorker(self.integrity_svc.verify_detailed, evd.file_path, evd.sha256_hash or "", parent=self)
        self._verify_worker = worker

        def on_done(res: dict):
            self.verify_disk_btn.setEnabled(True)
            self.verify_disk_btn.setText("🔐 Diskteki Dosyayı Doğrula")
            status = "Doğrulandı" if res["matched"] else "Uyuşmazlık"
            self.integrity_svc.add_custody_entry(
                evd.case_id,
                evd.id,
                "Bütünlük Doğrulama",
                "Çalışma Kopyası",
                evd.custodian or "Adli Bilişim Uzmanı",
                location="Analiz İstasyonu",
                acquire_method="Otomatik Hash Karşılaştırma",
                write_blocker_info="Salt Okunur Okuma",
                sha256_at_event=res["sha256"],
                sha512_at_event=res["sha512"],
                verification_status=status,
                notes=f"SHA-256 doğrulama sonucu: {status}",
            )
            self.refresh_records()
            QMessageBox.information(self, "Bütünlük Sonucu", f"SHA-256 Doğrulama Durumu: {status}\nHesaplanan: {res['sha256']}")

        def on_err(err: str):
            self.verify_disk_btn.setEnabled(True)
            self.verify_disk_btn.setText("🔐 Diskteki Dosyayı Doğrula")
            QMessageBox.critical(self, "Bütünlük Hatası", err)

        worker.finished_result.connect(on_done)
        worker.failed.connect(on_err)
        worker.start()

    def _activate_selected_evidence(self):
        rec = self.table.get_selected_record()
        if rec:
            label = f"{rec['Delil No']} ({rec['Marka / Model']})"
            self.activeEvidenceSelected.emit(rec["id"], label)
            QMessageBox.information(self, "Aktif Delil", f"Aktif delil seçildi:\n{label}")

    def _open_intake_dialog(self):
        cases = self.case_svc.list_cases()
        if not cases:
            QMessageBox.warning(self, "Vaka Gerekli", "Delil kabul etmek için önce bir vaka oluşturmalısınız.")
            return

        dlg = QDialog(self)
        dlg.setWindowTitle("Yeni Dijital Delil Kabul Formu")
        dlg.setMinimumWidth(520)
        lay = QVBoxLayout(dlg)
        form = QFormLayout()

        cb_case = QComboBox()
        for c in cases:
            cb_case.addItem(f"{c.case_number} - {c.title}", c.id)

        evd_num = QLineEdit(self.svc.generate_evidence_number(cb_case.currentData()))
        cb_type = QComboBox()
        cb_type.setEditable(True)
        cb_type.addItems(["USB Flash Bellek", "Disk İmajı (E01/RAW)", "NVMe / SSD", "RAM Dökümü", "Mobil Yedek", "Diğer"])
        brand = QLineEdit()
        model = QLineEdit()
        serial = QLineEdit()
        cap_gb = QLineEdit()
        cap_gb.setPlaceholderText("Örn: 64")
        delivered_by = QLineEdit("Olay Yeri Müdahale Ekibi")
        custodian = QLineEdit("Adli Bilişim Uzmanı")
        tool = QLineEdit()
        tool.setPlaceholderText("Örn: Tableau T8u / Donanımsal Yazma Engelleyici (Belirtilmedi)")
        wb_chk = QCheckBox("Donanımsal Yazma Engelleyici (Write-Blocker) Kullanıldı")
        wb_chk.setChecked(False)

        file_row = QHBoxLayout()
        file_path_ed = QLineEdit()
        file_path_ed.setPlaceholderText("Opsiyonel adli imaj veya dosya yolu...")
        browse_btn = QPushButton("Seç & Hashle")
        file_row.addWidget(file_path_ed)
        file_row.addWidget(browse_btn)

        sha256_ed = QLineEdit()
        sha256_ed.setStyleSheet("font-family: Consolas; font-size: 11px;")
        sha512_ed = QLineEdit()
        sha512_ed.setStyleSheet("font-family: Consolas; font-size: 11px;")
        notes_ed = QTextEdit()
        notes_ed.setFixedHeight(65)

        def pick_and_hash():
            fp, _ = QFileDialog.getOpenFileName(dlg, "Delil Dosyası / İmaj Seç")
            if not fp:
                return
            file_path_ed.setText(fp)
            browse_btn.setEnabled(False)
            browse_btn.setText("⏳ 0%")
            hw = HashWorker(fp, parent=dlg)
            dlg._hash_worker = hw
            hw.progress.connect(lambda p: browse_btn.setText(f"⏳ %{p}"))

            def on_hashed(res: dict):
                sha256_ed.setText(res["sha256"])
                sha512_ed.setText(res["sha512"])
                cap_gb.setText(f"{res['file_size'] / (1024**3):.4f}")
                browse_btn.setEnabled(True)
                browse_btn.setText("Seç & Hashle")

            def on_err(err: str):
                browse_btn.setEnabled(True)
                browse_btn.setText("Seç & Hashle")
                QMessageBox.warning(dlg, "Hash Hatası", err)

            hw.finished_result.connect(on_hashed)
            hw.failed.connect(on_err)
            hw.start()

        browse_btn.clicked.connect(pick_and_hash)

        form.addRow("İlgili Vaka *:", cb_case)
        form.addRow("Delil No *:", evd_num)
        form.addRow("Delil Türü *:", cb_type)
        form.addRow("Marka:", brand)
        form.addRow("Model:", model)
        form.addRow("Seri Numarası:", serial)
        form.addRow("Kapasite (GB):", cap_gb)
        form.addRow("Teslim Eden:", delivered_by)
        form.addRow("Teslim Alan:", custodian)
        form.addRow("Edinim Aracı:", tool)
        form.addRow("", wb_chk)
        form.addRow("İmaj / Dosya:", file_row)
        form.addRow("SHA-256:", sha256_ed)
        form.addRow("SHA-512:", sha512_ed)
        form.addRow("Kabul Notları:", notes_ed)
        lay.addLayout(form)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        cancel_btn = QPushButton("İptal")
        cancel_btn.clicked.connect(dlg.reject)
        save_btn = QPushButton("Delili Envantere Ekle")
        save_btn.setObjectName("primaryBtn")
        btn_row.addWidget(cancel_btn)
        btn_row.addWidget(save_btn)
        lay.addLayout(btn_row)

        def submit():
            cap_bytes = None
            try:
                if cap_gb.text().strip():
                    cap_bytes = int(float(cap_gb.text().strip()) * (1024 ** 3))
            except ValueError:
                QMessageBox.warning(dlg, "Hata", "Kapasite sayısal olmalıdır.")
                return

            evd = self.svc.add_evidence(
                case_id=cb_case.currentData(),
                evidence_number=evd_num.text(),
                device_type=cb_type.currentText(),
                brand=brand.text(),
                model=model.text(),
                serial=serial.text(),
                capacity_bytes=cap_bytes,
                custodian=custodian.text(),
                acquire_tool=tool.text(),
                write_blocker_used=wb_chk.isChecked(),
                sha256_hash=sha256_ed.text(),
                sha512_hash=sha512_ed.text(),
                file_path=file_path_ed.text(),
                notes=notes_ed.toPlainText(),
                delivered_by=delivered_by.text(),
            )
            dlg.accept()
            self.refresh_records()
            self.activeEvidenceSelected.emit(evd.id, f"{evd.evidence_number} ({evd.brand} {evd.model})")

        save_btn.clicked.connect(submit)
        dlg.exec()
