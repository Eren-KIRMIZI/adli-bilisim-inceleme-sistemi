"""Settings, Forensic Policy & Dependency Licenses Page."""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QComboBox
)
from PySide6.QtCore import Signal

from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.status_indicator import StatusBadge

VERIFIED_DEPENDENCIES = [
    {"Durum": "Doğrulandı", "Paket": "Python", "Sürüm": "3.11+", "Lisans": "PSF License", "Kullanım": "Çekirdek çalışma zamanı ve standart binary/sqlite kütüphaneleri"},
    {"Durum": "Doğrulandı", "Paket": "PySide6", "Sürüm": "6.6+", "Lisans": "LGPL-3.0", "Kullanım": "Masaüstü Qt Widgets arayüz katmanı"},
    {"Durum": "Doğrulandı", "Paket": "SQLAlchemy", "Sürüm": "2.0+", "Lisans": "MIT", "Kullanım": "SQLite ORM veri kalıcılığı"},
    {"Durum": "Doğrulandı", "Paket": "Pydantic", "Sürüm": "2.5+", "Lisans": "MIT", "Kullanım": "Standart artefakt çıktı doğrulama şemaları"},
    {"Durum": "Doğrulandı", "Paket": "ReportLab", "Sürüm": "4.0+", "Lisans": "BSD", "Kullanım": "Çevrimdışı PDF adli rapor üretimi"},
    {"Durum": "Doğrulandı", "Paket": "Jinja2", "Sürüm": "3.1+", "Lisans": "BSD-3-Clause", "Kullanım": "Denetlenebilir HTML adli rapor şablonlama"},
    {"Durum": "Doğrulandı", "Paket": "NetworkX", "Sürüm": "3.x", "Lisans": "BSD-3-Clause", "Kullanım": "Bulgu ilişki grafiği topoloji ve düzen hesaplaması"},
    {"Durum": "Doğrulandı", "Paket": "Matplotlib", "Sürüm": "3.8+", "Lisans": "PSF / BSD", "Kullanım": "Görselleştirme desteği"},
    {"Durum": "Doğrulandı", "Paket": "pytest", "Sürüm": "7.4+", "Lisans": "MIT", "Kullanım": "Otomatik birim ve arayüz test doğrulaması"},
]


class SettingsPage(QWidget):
    """Application settings, forensic compliance rules, and verified license registry."""

    themeSelected = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 18, 24, 18)
        main_layout.setSpacing(14)

        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Ayarlar & Açık Kaynak Lisansları"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()
        header_bar.addWidget(StatusBadge("Tamamen Çevrimdışı • Ticari Araç Bağımsız", "verified"))
        main_layout.addLayout(header_bar)

        # Appearance & Policy Card
        cfg_card = QFrame()
        cfg_card.setObjectName("surfaceCard")
        c_lay = QVBoxLayout(cfg_card)
        c_lay.setContentsMargins(16, 14, 16, 14)
        c_lay.setSpacing(8)

        title = QLabel("Arayüz ve Adli Çalışma Politikası")
        title.setObjectName("sectionTitle")
        c_lay.addWidget(title)

        theme_row = QHBoxLayout()
        theme_row.addWidget(QLabel("Varsayılan Görünüm Teması:"))
        self.theme_combo = QComboBox()
        self.theme_combo.addItems(["Açık Mod (Forensic Light)", "Koyu Mod (Forensic Dark)"])
        self.theme_combo.setFixedWidth(240)
        self.theme_combo.currentIndexChanged.connect(
            lambda idx: self.themeSelected.emit("light" if idx == 0 else "dark")
        )
        theme_row.addWidget(self.theme_combo)
        theme_row.addStretch()
        c_lay.addLayout(theme_row)

        policy_lbl = QLabel(
            "• Orijinal delil üzerinde değişiklik yapılmaz; tüm dosya/imaj/SQLite işlemleri salt-okunur modda yürütülür.\n"
            "• SQLite WAL + synchronous=FULL ve atomik oturum kurtarma ile elektrik kesintisi/çökme koruması aktiftir.\n"
            "• Docker, WSL veya zorunlu bulut API bağımlılığı yoktur; doğrudan Windows üzerinde çalışır.\n"
            "• Ana analiz motorları (NTFS/MFT, Registry Hive, EVTX, LNK, Prefetch, USBSTOR, File Carving) özgün olarak geliştirilmiştir."
        )
        policy_lbl.setObjectName("mutedLabel")
        c_lay.addWidget(policy_lbl)
        main_layout.addWidget(cfg_card)

        # Licenses Card
        lic_card = QFrame()
        lic_card.setObjectName("surfaceCard")
        l_lay = QVBoxLayout(lic_card)
        l_lay.setContentsMargins(16, 14, 16, 14)
        l_lay.setSpacing(8)

        lic_title = QLabel("Doğrulanmış Bağımlılıklar ve Açık Kaynak Lisans Kaydı (LICENSES.md)")
        lic_title.setObjectName("sectionTitle")
        l_lay.addWidget(lic_title)

        self.lic_table = ForensicDataTable(["Durum", "Paket", "Sürüm", "Lisans", "Kullanım"], self)
        self.lic_table.set_records(VERIFIED_DEPENDENCIES)
        l_lay.addWidget(self.lic_table)

        main_layout.addWidget(lic_card, 1)
