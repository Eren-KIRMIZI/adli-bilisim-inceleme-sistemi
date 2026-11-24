"""USB Forensics Analysis Page adhering to NIST SP 800-86 standard."""

import json
from datetime import datetime
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, 
    QPushButton, QComboBox, QSplitter, QFileDialog, QMessageBox, QApplication
)
from PySide6.QtCore import Qt
from src.usb_engine.usb_service import UsbService
from src.database.models import UsbDeviceRecord
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.search_field import ForensicSearchField
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.metadata_panel import MetadataPanel
from src.ui.components.status_indicator import StatusBadge

class UsbAnalysisPage(QWidget):
    """Deep forensic inspection page for Windows USB device artifacts."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.usb_service = UsbService()

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 20, 24, 20)
        main_layout.setSpacing(14)

        # 1. Breadcrumb & Title Area
        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Windows Forensics", "USB Cihaz İnceleme"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()

        self.summary_badge = StatusBadge("4 Cihaz Kaydı", "info")
        header_bar.addWidget(self.summary_badge)

        self.suspicious_badge = StatusBadge("1 Şüpheli Anomali", "warning")
        header_bar.addWidget(self.suspicious_badge)

        main_layout.addLayout(header_bar)

        # 2. Control & Filter Toolbar
        toolbar = QHBoxLayout()
        toolbar.setSpacing(10)

        # Search field with clear and instant debounce
        self.search_field = ForensicSearchField("USB Cihazı, Seri No, VID/PID, Sürücü veya Kullanıcı Ara...")
        self.search_field.searchChanged.connect(self._on_search)
        toolbar.addWidget(self.search_field, 2)

        # Category / Class Filter dropdown
        self.filter_combo = QComboBox()
        self.filter_combo.addItems([
            "Tüm Aygıt Sınıfları",
            "Yalnızca Depolama (USBSTOR)",
            "Yalnızca Şüpheli Cihazlar",
            "Taşınabilir Cihazlar (MTP/PTP)",
            "HID / Giriş Birimleri"
        ])
        self.filter_combo.currentIndexChanged.connect(self._apply_filters)
        self.filter_combo.setFixedWidth(200)
        toolbar.addWidget(self.filter_combo)

        # Action Buttons
        scan_live_btn = QPushButton("⚡ Canlı Sistemden Çek")
        scan_live_btn.setObjectName("primaryBtn")
        scan_live_btn.setToolTip("Windows Registry üzerinden aktif ve geçmiş USB bağlantılarını salt-okunur tara.")
        scan_live_btn.clicked.connect(self._scan_live)
        toolbar.addWidget(scan_live_btn)

        load_hive_btn = QPushButton("📁 Hive Yükle (SYSTEM)")
        load_hive_btn.setToolTip("Çevrimdışı alınmış SYSTEM Registry kovanını ayrıştır.")
        load_hive_btn.clicked.connect(self._load_hive)
        toolbar.addWidget(load_hive_btn)

        export_btn = QPushButton("Dışa Aktar (CSV)")
        export_btn.clicked.connect(self._export_csv)
        toolbar.addWidget(export_btn)

        main_layout.addLayout(toolbar)

        # 3. Main Splitter: Left DataTable + Right Property Inspector
        splitter = QSplitter(Qt.Horizontal)
        splitter.setChildrenCollapsible(False)

        # Left Container: Data Table
        table_container = QFrame()
        table_container.setObjectName("surfaceCard")
        tc_layout = QVBoxLayout(table_container)
        tc_layout.setContentsMargins(12, 12, 12, 12)
        tc_layout.setSpacing(8)

        t_header = QHBoxLayout()
        tbl_title = QLabel("Tespit Edilen USB Donanım & Kayıt Defteri İzleri")
        tbl_title.setStyleSheet("font-size: 13px; font-weight: 700; color: #1D2733;")
        t_header.addWidget(tbl_title)
        t_header.addStretch()

        help_lbl = QLabel("Detaylı metadata ve hex incelemesi için satıra tıklayın")
        help_lbl.setStyleSheet("font-size: 11px; color: #98A2B3;")
        t_header.addWidget(help_lbl)
        tc_layout.addLayout(t_header)

        headers = [
            "Durum", "Cihaz Adı", "Üretici", "VID", "PID", 
            "Seri Numarası", "Sürücü", "İlk Bağlantı (UTC)", 
            "Son Bağlantı (UTC)", "Kullanıcı", "Güvenilirlik"
        ]
        self.table = ForensicDataTable(headers, self)
        self.table.rowSelected.connect(self._on_device_selected)
        tc_layout.addWidget(self.table)

        splitter.addWidget(table_container)

        # Right Container: Metadata & Technical Inspector Panel
        self.meta_panel = MetadataPanel("USB Cihaz Detayları & Metadata", self)
        splitter.addWidget(self.meta_panel)

        splitter.setStretchFactor(0, 7)
        splitter.setStretchFactor(1, 3)
        main_layout.addWidget(splitter, 1)

        # Load initial device records
        self._all_records = []
        self.refresh_records()

    def refresh_records(self):
        """Fetch records from UsbService and populate the table."""
        devices = self.usb_service.list_devices()
        self._all_records = []

        suspicious_count = 0
        for dev in devices:
            if dev.is_suspicious:
                suspicious_count += 1

            status_str = dev.status or ("Şüpheli Cihaz" if dev.is_suspicious else "Normal")
            rec_dict = {
                "id": dev.id,
                "Durum": status_str,
                "Cihaz Adı": dev.device_name or "Bilinmeyen USB Cihazı",
                "Üretici": dev.vendor or "-",
                "Model": dev.product or "-",
                "VID": dev.vid or "-",
                "PID": dev.pid or "-",
                "Seri Numarası": dev.serial_number or "-",
                "Sürücü Harfi": dev.drive_letter or "-",
                "Sürücü": dev.drive_letter or "-",
                "Cihaz Sınıfı": dev.device_class or "USBSTOR",
                "İlk Bağlantı": dev.first_connected.strftime("%Y-%m-%d %H:%M:%S") if dev.first_connected else "-",
                "İlk Bağlantı (UTC)": dev.first_connected.strftime("%Y-%m-%d %H:%M:%S") if dev.first_connected else "-",
                "Son Bağlantı": dev.last_connected.strftime("%Y-%m-%d %H:%M:%S") if dev.last_connected else "-",
                "Son Bağlantı (UTC)": dev.last_connected.strftime("%Y-%m-%d %H:%M:%S") if dev.last_connected else "-",
                "Son Çıkarılma": dev.last_removed.strftime("%Y-%m-%d %H:%M:%S") if dev.last_removed else "-",
                "İlişkili Kullanıcı": dev.user_account or "SYSTEM / Genel",
                "Kullanıcı": dev.user_account or "SYSTEM / Genel",
                "User SID": dev.user_sid or "S-1-5-18",
                "Volume GUID": dev.volume_guid or "-",
                "Kaynak Kayıt": dev.registry_source_key or "-",
                "Hive Dosyası": "SYSTEM Hive (CurrentControlSet)",
                "NIST Kuralı": "NIST SP 800-86 §5.2 USBSTOR Analysis",
                "Güvenilirlik": f"%{dev.confidence}",
                "Doğrulama": "Kayıt Defteri + EventLog 2003 Eşleşmesi",
                "is_suspicious": dev.is_suspicious,
                "raw_details": dev.raw_details or "{}"
            }
            self._all_records.append(rec_dict)

        self.summary_badge.set_status(f"{len(self._all_records)} Cihaz Kaydı", "info")
        self.suspicious_badge.set_status(f"{suspicious_count} Şüpheli Anomali", "warning" if suspicious_count > 0 else "verified")

        self._apply_filters()

        # Select first row by default if exists
        if self._all_records:
            self._on_device_selected(self._all_records[0])

    def _apply_filters(self):
        filter_type = self.filter_combo.currentText()
        records = list(self._all_records)

        if filter_type == "Yalnızca Depolama (USBSTOR)":
            records = [r for r in records if "usbstor" in r.get("Cihaz Sınıfı", "").lower()]
        elif filter_type == "Yalnızca Şüpheli Cihazlar":
            records = [r for r in records if r.get("is_suspicious", False)]
        elif filter_type == "Taşınabilir Cihazlar (MTP/PTP)":
            records = [r for r in records if "mtp" in r.get("Cihaz Sınıfı", "").lower()]
        elif filter_type == "HID / Giriş Birimleri":
            records = [r for r in records if "hid" in r.get("Cihaz Sınıfı", "").lower()]

        # Apply search query if present
        query = self.search_field.text()
        if query:
            q = query.lower()
            records = [r for r in records if any(q in str(v).lower() for v in r.values())]

        self.table.set_records(records)

    def _on_search(self, query: str):
        self._apply_filters()

    def _on_device_selected(self, record: dict):
        # Prepare raw bytes for hex viewer
        raw_json_str = record.get("raw_details", "{}")
        try:
            raw_bytes = json.dumps(json.loads(raw_json_str), indent=2).encode("utf-8")
        except Exception:
            raw_bytes = raw_json_str.encode("utf-8")

        self.meta_panel.populate(record, raw_hex=raw_bytes)

    def _scan_live(self):
        try:
            new_records = self.usb_service.scan_live_system()
            self.refresh_records()
            QMessageBox.information(
                self, 
                "Canlı Tarama Tamamlandı", 
                f"Canlı Windows Registry (USBSTOR & MountedDevices) üzerinden {len(new_records)} kayıt başarıyla okundu."
            )
        except Exception as e:
            QMessageBox.critical(self, "Tarama Hatası", f"Canlı tarama gerçekleştirilemedi: {e}")

    def _load_hive(self):
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "SYSTEM Registry Kovanı Seç", 
            "", 
            "Registry Kovanları (*; SYSTEM; *.hiv; *.dat);;Tüm Dosyalar (*.*)"
        )
        if not file_path:
            return
        try:
            records = self.usb_service.parse_offline_hive(file_path)
            self.refresh_records()
            QMessageBox.information(
                self, 
                "Hive Ayrıştırıldı", 
                f"{len(records)} adet USB artefaktı kovan dosyasından başarıyla çıkarıldı."
            )
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"Hive dosyası ayrıştırılamadı: {e}")

    def _export_csv(self):
        self.table.export_to_csv()
