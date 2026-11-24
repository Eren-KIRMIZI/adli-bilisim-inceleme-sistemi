# Modules

1. **Dashboard** (`dashboard_page.py`) — Vaka/delil/artefakt KPI özetleri, standart uyumluluk göstergeleri, denetim günlüğü (`AuditLog`).
2. **Case Management** (`case_engine/`) — Vaka numarası, soruşturma başlığı, sorumlu, kurum, tarihler, durum geçişleri ve bağlı delil özeti.
3. **Evidence Manager** (`evidence_engine/`) — Cihaz envanteri, seri no, kapasite, yazma engelleyici kaydı, tek geçişli SHA-256/512 ve dosya doğrulama.
4. **Integrity & Chain of Custody** (`integrity_engine/`) — `QThread` destekli SHA-256/512 hesaplama, hash karşılaştırma, teslim/erişim amacı kayıtları (`ChainOfCustodyEntry`).
5. **Disk Forensics** (`ntfs_engine/`) — RAW/E01 başlık kontrolü, MBR/GPT bölümleme, NTFS VBR/`$MFT` (aktif ve silinmiş kayıtlar, MACB), File Carving, 3 sütunlu gezgin + Hex görüntüleyici.
6. **Windows Forensics** (`registry_engine/`, `eventlog_engine/`) — Özgün `regf` Registry Hive ağacı, `ElfFile` EVTX olay günlükleri, `.lnk`, `.pf` Prefetch, `$I` Geri Dönüşüm Kutusu ve canlı Windows salt-okunur triage.
7. **USB Device Forensics** (`usb_engine/`) — VID/PID, seri no, sürücü harfi, `USBSTOR`/`MountedDevices` kayıtları, kullanıcı profili eşleşmesi ve BadUSB anomali işaretleme.
8. **Browser Forensics** (`browser_engine/`) — Chrome/Edge/Firefox salt-okunur SQLite (`?mode=ro`) geçmiş, indirme, arama terimi, yer imleri ve maskeli çerez metadata.
9. **Memory Forensics** (`memory_engine/`) — RAM döküm formatı (`PAGEDU64`, `PAGEDUMP`, `HIBR`, `ELF`, `LiME`), KDBG/PE modülleri, IOC taraması ve canlı Windows Toolhelp32 süreç listesi.
10. **File Analysis** (`file_engine/`) — Magic-byte imza tanıma, uzantı sahteciliği tespiti, Shannon entropisi, JPEG EXIF ayrıştırıcı, hex görüntüleme, diff ve duplicate taraması.
11. **Timeline Analysis** (`timeline_engine/`) — UTC standardizasyonu, orijinal damga & güvenilirlik koruması, saatlik yoğunluk grafiği, filtreleme ve olaylar arası $\Delta t$ hesabı.
12. **Evidence Relations** (`correlation_engine/`) — NetworkX + etkileşimli grafik; doğrulanabilir kanıtlı bağlantılar ile kanıtlanmamış zamansal hipotezlerin ayrımı.
13. **Report Generator** (`report_engine/`) — SWGDE/NIST uyumlu HTML (Jinja2) ve PDF (ReportLab) adli raporlar, canlı önizleme.
14. **Settings & Licenses** (`settings_page.py`) — Açık/Koyu tema seçimi, adli politikalar ve lisans tablosu (`LICENSES.md`).
