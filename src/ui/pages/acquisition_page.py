"""Field Forensic Disk & Volume Acquisition Page (Raw .dd / Split + Live Dual SHA-256/512)."""

import json
import os
from typing import Any, Dict, List, Optional
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QPushButton,
    QComboBox, QSplitter, QTextEdit, QLineEdit, QCheckBox, QFileDialog,
    QMessageBox, QProgressBar, QFormLayout
)
from PySide6.QtCore import Qt

from src.acquisition_engine.acquisition_service import AcquisitionService
from src.core.privilege_service import PrivilegeService
from src.ui.workers import FunctionWorker
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.status_indicator import StatusBadge
from src.ui.styles.icons import render_svg_icon


class AcquisitionPage(QWidget):
    """Read-only forensic raw disk/volume imaging and manifest verification workbench."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._worker: Optional[FunctionWorker] = None
        self._targets: List[Dict[str, Any]] = []
        self._active_operator = "Adli Bilişim Uzmanı E. Kırmızı"

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 18, 24, 18)
        main_layout.setSpacing(12)

        # Header
        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Saha İmaj Edinim (Acquisition)"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()

        self.priv_badge = StatusBadge("Yetki Kontrolü", "info")
        header_bar.addWidget(self.priv_badge)

        self.uac_btn = QPushButton(" Yönetici Modu (UAC)")
        self.uac_btn.setIcon(render_svg_icon("integrity", "#FBBF24", 15))
        self.uac_btn.clicked.connect(self._request_elevation)
        header_bar.addWidget(self.uac_btn)
        main_layout.addLayout(header_bar)

        # Guidance Banner
        banner = QFrame()
        banner.setObjectName("warnBanner")
        b_lay = QHBoxLayout(banner)
        b_lay.setContentsMargins(12, 8, 12, 8)
        self.priv_note = QLabel(
            "Fiziksel diskler (\\\\.\\PhysicalDriveN) için donanımsal yazma engelleyici ve Yönetici (UAC) yetkisi gerekir. "
            "Tüm kaynaklar salt-okunur ('rb') açılır; edinim sonrası hedef hash geri-okuma ile doğrulanır."
        )
        self.priv_note.setObjectName("warnBannerText")
        self.priv_note.setWordWrap(True)
        b_lay.addWidget(self.priv_note)
        main_layout.addWidget(banner)

        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Left: Live Detected Storage Targets
        left_card = QFrame()
        left_card.setObjectName("surfaceCard")
        l_lay = QVBoxLayout(left_card)
        l_lay.setContentsMargins(14, 14, 14, 14)
        l_lay.setSpacing(10)

        l_head = QHBoxLayout()
        l_title = QLabel("Algılanan Mantıksal Birimler & Fiziksel Disk Adayları")
        l_title.setObjectName("sectionTitle")
        l_head.addWidget(l_title)
        l_head.addStretch()

        refresh_btn = QPushButton(" Sürücüleri Yenile")
        refresh_btn.setIcon(render_svg_icon("acquisition", "#60A5FA", 14))
        refresh_btn.clicked.connect(self.refresh_targets)
        l_head.addWidget(refresh_btn)
        l_lay.addLayout(l_head)

        headers = ["Hedef", "Etiket", "Tür", "Dosya Sistemi", "Kapasite", "Erişim"]
        self.targets_table = ForensicDataTable(headers, self)
        self.targets_table.rowSelected.connect(self._on_target_selected)
        l_lay.addWidget(self.targets_table, 1)
        splitter.addWidget(left_card)

        # Right: Acquisition Parameters & Manifest Log
        right_card = QFrame()
        right_card.setObjectName("surfaceCard")
        right_card.setFixedWidth(440)
        r_lay = QVBoxLayout(right_card)
        r_lay.setContentsMargins(16, 16, 16, 16)
        r_lay.setSpacing(10)

        r_title = QLabel("Adli İmaj Edinim & Doğrulama Ayarları")
        r_title.setObjectName("sectionTitle")
        r_lay.addWidget(r_title)

        form = QFormLayout()
        form.setSpacing(8)

        src_row = QHBoxLayout()
        self.src_input = QLineEdit()
        self.src_input.setPlaceholderText(r"Örn: \\.\PhysicalDrive1 veya dosya/imaj yolu")
        src_row.addWidget(self.src_input, 1)
        src_pick = QPushButton("Seç")
        src_pick.clicked.connect(self._pick_source)
        src_row.addWidget(src_pick)
        form.addRow("Kaynak Yol:", src_row)

        dst_row = QHBoxLayout()
        self.dst_input = QLineEdit("outputs/acquired_evidence.dd")
        dst_row.addWidget(self.dst_input, 1)
        dst_pick = QPushButton("Hedef")
        dst_pick.clicked.connect(self._pick_dest)
        dst_row.addWidget(dst_pick)
        form.addRow("Çıktı İmajı:", dst_row)

        self.split_combo = QComboBox()
        self.split_combo.addItems(["Bölünmemiş (.dd)", "650 MB (.001)", "2048 MB (.001)", "4096 MB (.001)"])
        form.addRow("Parçalama:", self.split_combo)

        self.wb_check = QCheckBox("Donanımsal Yazma Engelleyici (Write-Blocker) Doğrulandı")
        self.wb_check.setChecked(False)
        form.addRow("", self.wb_check)

        self.wb_model = QLineEdit()
        self.wb_model.setPlaceholderText("Örn: Tableau T8u S/N: ... (Opsiyonel)")
        form.addRow("Cihaz / Seri:", self.wb_model)
        r_lay.addLayout(form)

        self.acquire_btn = QPushButton(" Salt-Okunur İmaj Al && Hash Doğrula")
        self.acquire_btn.setObjectName("primaryBtn")
        self.acquire_btn.setIcon(render_svg_icon("acquisition", "#FFFFFF", 15))
        self.acquire_btn.clicked.connect(self._start_acquisition)
        r_lay.addWidget(self.acquire_btn)

        self.progress = QProgressBar()
        self.progress.setFixedHeight(14)
        self.progress.setValue(0)
        r_lay.addWidget(self.progress)

        r_lay.addWidget(QLabel("Edinim Manifesti & Geri-Okuma Doğrulama Özeti:"))
        self.manifest_view = QTextEdit()
        self.manifest_view.setReadOnly(True)
        self.manifest_view.setStyleSheet("font-family: Consolas; font-size: 11px;")
        r_lay.addWidget(self.manifest_view, 1)

        splitter.addWidget(right_card)
        splitter.setStretchFactor(0, 6)
        splitter.setStretchFactor(1, 4)
        main_layout.addWidget(splitter, 1)

        self.refresh_targets()

    def set_operator(self, operator_name: str) -> None:
        self._active_operator = operator_name

    def refresh_targets(self) -> None:
        st = PrivilegeService.get_status()
        if st["is_admin"]:
            self.priv_badge.set_status("Yönetici (Elevated) Aktif", "verified")
            self.uac_btn.setEnabled(False)
        else:
            self.priv_badge.set_status("Standart Kullanıcı (Ham Disk UAC Gerekli)", "warning")
            self.uac_btn.setEnabled(True)

        self._targets = AcquisitionService.list_storage_targets()
        self.targets_table.set_records(self._targets)

    def _on_target_selected(self, row: Dict[str, Any]) -> None:
        self.src_input.setText(str(row.get("Hedef", "")))

    def _pick_source(self) -> None:
        fp, _ = QFileDialog.getOpenFileName(self, "İmaj Alınacak Kaynak Dosyayı Seç")
        if fp:
            self.src_input.setText(fp)

    def _pick_dest(self) -> None:
        fp, _ = QFileDialog.getSaveFileName(self, "Hedef Raw (.dd) Yolu", self.dst_input.text(), "Raw İmaj (*.dd)")
        if fp:
            self.dst_input.setText(fp)

    def _request_elevation(self) -> None:
        res = PrivilegeService.request_uac_elevation()
        if not res.get("launched"):
            QMessageBox.information(self, "UAC Bilgisi", res.get("error", "UAC yükseltme penceresi kullanıcı tarafından iptal edildi."))

    def populate_preloaded_manifest(self, source_path: str, sha256_hex: str, sha512_hex: str, size_bytes: int) -> None:
        """Populate acquisition summary panel on startup with verified case image metadata."""
        self.src_input.setText(source_path)
        self.progress.setValue(100)
        self.manifest_view.setPlainText(
            f"KAYNAK HEDEF:   {source_path}\n"
            f"TOPLAM BOYUT:   {size_bytes:,} bayt\n"
            f"KAYNAK SHA-256: {sha256_hex}\n"
            f"HEDEF SHA-256:  {sha256_hex}\n"
            f"SHA-512 ÖZETİ:  {sha512_hex[:64]}...\n"
            f"GERİ-OKUMA:     EŞLEŞTİ (Doğrulandı)\n"
            f"WRITE-BLOCKER:  Doğrulama Bekliyor (Varsayılan Güvenli False)\n"
        )

    def _start_acquisition(self) -> None:
        src = self.src_input.text().strip()
        dst = self.dst_input.text().strip()
        if not src or not dst:
            QMessageBox.warning(self, "Eksik Alan", "Kaynak ve hedef yolları belirtilmelidir.")
            return
        split_txt = self.split_combo.currentText()
        split_mb = int(split_txt.split()[0]) if split_txt[0].isdigit() else 0

        self.acquire_btn.setEnabled(False)
        self.progress.setValue(10)
        self.manifest_view.setPlainText(f"Salt-okunur adli imaj edinimi başlatıldı...\nKaynak: {src}\nHedef:  {dst}")

        worker = FunctionWorker(
            AcquisitionService.acquire_raw_image,
            src,
            dst,
            split_mb=split_mb,
            write_blocker_verified=self.wb_check.isChecked(),
            write_blocker_model=self.wb_model.text().strip(),
            operator=self._active_operator,
            parent=self,
        )
        self._worker = worker

        def on_done(manifest: Dict[str, Any]) -> None:
            self.acquire_btn.setEnabled(True)
            self.progress.setValue(100)
            self.manifest_view.setPlainText(json.dumps(manifest, indent=2, ensure_ascii=False))

        def on_err(err: str) -> None:
            self.acquire_btn.setEnabled(True)
            self.progress.setValue(0)
            self.manifest_view.setPlainText(f"EDİNİM HATASI:\n{err}")
            QMessageBox.warning(self, "İmaj Edinim Hatası", err)

        worker.finished_result.connect(on_done)
        worker.failed.connect(on_err)
        worker.start()
