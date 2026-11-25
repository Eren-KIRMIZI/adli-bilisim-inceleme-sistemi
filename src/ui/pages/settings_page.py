"""Settings, Forensic Policy & Dependency Licenses Page."""

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame
)

from src.core.auth_service import AuthService
from src.core.signing_service import SigningService
from src.ui.components.breadcrumb import Breadcrumb
from src.ui.components.data_table import ForensicDataTable
from src.ui.components.status_indicator import StatusBadge

VERIFIED_DEPENDENCIES = [
    {"Durum": "Doğrulandı", "Paket": "Python", "Sürüm": "3.11+", "Lisans": "PSF License", "Kullanım": "Çekirdek çalışma zamanı ve standart binary/sqlite kütüphaneleri"},
    {"Durum": "Doğrulandı", "Paket": "PySide6", "Sürüm": "6.6+", "Lisans": "LGPL-3.0", "Kullanım": "Masaüstü Qt Widgets arayüz katmanı"},
    {"Durum": "Doğrulandı", "Paket": "SQLAlchemy", "Sürüm": "2.0+", "Lisans": "MIT", "Kullanım": "SQLite ORM veri kalıcılığı"},
    {"Durum": "Doğrulandı", "Paket": "Pydantic", "Sürüm": "2.5+", "Lisans": "MIT", "Kullanım": "Standart artefakt çıktı doğrulama şemaları"},
    {"Durum": "Doğrulandı", "Paket": "cryptography", "Sürüm": "41.0+", "Lisans": "Apache-2.0 / BSD-3-Clause", "Kullanım": "X.509 RSA-PSS-SHA256 dijital rapor imzalama ve doğrulama"},
    {"Durum": "Doğrulandı", "Paket": "ReportLab", "Sürüm": "4.0+", "Lisans": "BSD", "Kullanım": "Çevrimdışı PDF adli rapor üretimi"},
    {"Durum": "Doğrulandı", "Paket": "Jinja2", "Sürüm": "3.1+", "Lisans": "BSD-3-Clause", "Kullanım": "Denetlenebilir HTML adli rapor şablonlama"},
    {"Durum": "Doğrulandı", "Paket": "NetworkX", "Sürüm": "3.x", "Lisans": "BSD-3-Clause", "Kullanım": "Bulgu ilişki grafiği topoloji ve düzen hesaplaması"},
    {"Durum": "Doğrulandı", "Paket": "Matplotlib", "Sürüm": "3.8+", "Lisans": "PSF / BSD", "Kullanım": "Görselleştirme desteği"},
    {"Durum": "Doğrulandı", "Paket": "pytest", "Sürüm": "7.4+", "Lisans": "MIT", "Kullanım": "Otomatik birim ve arayüz test doğrulaması"},
]


class SettingsPage(QWidget):
    """Application settings, RBAC users, X.509 lab certificate, and verified license registry."""

    def __init__(self, db_path: str = "data/forensics.db", cert_dir: str = "data/certs", parent=None):
        super().__init__(parent)
        self.auth_svc = AuthService(db_path=db_path)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(24, 18, 24, 18)
        main_layout.setSpacing(12)

        header_bar = QHBoxLayout()
        self.breadcrumb = Breadcrumb(["Adli Bilişim", "Ayarlar, RBAC & Lisanslar"])
        header_bar.addWidget(self.breadcrumb)
        header_bar.addStretch()
        header_bar.addWidget(StatusBadge("Tamamen Çevrimdışı • X.509 & RBAC Aktif", "verified"))
        main_layout.addLayout(header_bar)

        # Appearance, Certificate & Policy Card
        cfg_card = QFrame()
        cfg_card.setObjectName("surfaceCard")
        c_lay = QVBoxLayout(cfg_card)
        c_lay.setContentsMargins(16, 12, 16, 12)
        c_lay.setSpacing(8)

        title = QLabel("Arayüz, Kurumsal X.509 Sertifikası ve Adli Çalışma Politikası")
        title.setObjectName("sectionTitle")
        c_lay.addWidget(title)

        theme_row = QHBoxLayout()
        theme_row.addWidget(QLabel("Arayüz Modu:"))
        theme_row.addWidget(StatusBadge("Forensic Dark Console (Sabit)", "info"))
        cert = SigningService.ensure_lab_certificate(cert_dir=cert_dir)
        theme_row.addWidget(QLabel("  X.509 İmza Parmak İzi:"))
        theme_row.addWidget(StatusBadge(f"SHA-256: {cert['fingerprint_sha256'][:16]}...", "verified"))
        theme_row.addStretch()
        c_lay.addLayout(theme_row)

        policy_lbl = QLabel(
            "• Orijinal delil üzerinde değişiklik yapılmaz; tüm dosya/imaj/SQLite işlemleri salt-okunur modda yürütülür.\n"
            "• SQLite WAL + synchronous=FULL, PBKDF2-HMAC-SHA256 kullanıcı RBAC yetkileri ve RSA-PSS-SHA256 X.509 imza doğrulaması aktiftir.\n"
            "• Ana analiz motorları (NTFS/MFT, Registry Hive, EVTX, LNK, Prefetch, USBSTOR, File Carving) özgün olarak geliştirilmiştir."
        )
        policy_lbl.setObjectName("mutedLabel")
        c_lay.addWidget(policy_lbl)
        main_layout.addWidget(cfg_card)

        # RBAC Users Table
        rbac_card = QFrame()
        rbac_card.setObjectName("surfaceCard")
        r_lay = QVBoxLayout(rbac_card)
        r_lay.setContentsMargins(16, 12, 16, 12)
        r_lay.setSpacing(6)
        rbac_title = QLabel("Kurumsal Çoklu Kullanıcı & Rol Yetkilendirme Matrisi (RBAC)")
        rbac_title.setObjectName("sectionTitle")
        r_lay.addWidget(rbac_title)

        self.rbac_table = ForensicDataTable(["Durum", "Kullanıcı", "Ad Soyad", "Rol", "Yetkiler"], self)
        rbac_rows = [
            {
                "Durum": "Doğrulandı" if u["is_active"] else "Pasif",
                "Kullanıcı": u["username"],
                "Ad Soyad": u["full_name"],
                "Rol": u["role_tr"],
                "Yetkiler": u["permissions"],
            }
            for u in self.auth_svc.list_users()
        ]
        self.rbac_table.set_records(rbac_rows)
        r_lay.addWidget(self.rbac_table)
        main_layout.addWidget(rbac_card, 1)

        # Licenses Card
        lic_card = QFrame()
        lic_card.setObjectName("surfaceCard")
        l_lay = QVBoxLayout(lic_card)
        l_lay.setContentsMargins(16, 12, 16, 12)
        l_lay.setSpacing(6)

        lic_title = QLabel("Doğrulanmış Bağımlılıklar ve Açık Kaynak Lisans Kaydı (LICENSES.md)")
        lic_title.setObjectName("sectionTitle")
        l_lay.addWidget(lic_title)

        self.lic_table = ForensicDataTable(["Durum", "Paket", "Sürüm", "Lisans", "Kullanım"], self)
        self.lic_table.set_records(VERIFIED_DEPENDENCIES)
        l_lay.addWidget(self.lic_table)

        main_layout.addWidget(lic_card, 1)
