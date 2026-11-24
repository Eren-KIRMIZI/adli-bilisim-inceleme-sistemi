# Testing

Her analiz motoru, veri katmanı, kurtarma mekanizması ve arayüz bileşeni otomatik testlere sahiptir. Testlerde gerçek kişilere ait veriler yerine kod içinde üretilen sentetik ikili (binary) ve SQLite adli örnekler kullanılır.

## Test Kapsamı (`tests/` — 43 Test)
- `test_case_evidence_integrity.py`: Vaka yaşam döngüsü, delil kabulü, muhafaza zinciri ve SHA-256/512 doğrulama.
- `test_database.py`: SQLite şema oluşturma ve sentetik vaka seed doğrulaması.
- `test_recovery.py`: SQLite WAL modu, beklenmedik elektrik kesintisi/çökme kurtarma ve `.sha256` yedek doğrulaması.
- `test_disk_and_ntfs.py`: Sentetik MBR, GPT, NTFS VBR, `$MFT` (aktif/silinmiş), File Carving ve E01 uyarı davranışı.
- `test_windows_forensics.py`: Sentetik `regf` Registry Hive, `ElfFile` EVTX, `.lnk`, `.pf`, `$I` ayrıştırma ve bozuk dosya hata davranışı.
- `test_usb_service.py`: USBSTOR kayıtları, string ayrıştırma ve şüpheli cihaz işaretleme.
- `test_file_browser_memory.py`: EXIF JPEG, uzantı sahteciliği, diff/duplicate, Chrome SQLite/maskeli çerezler ve `PAGEDU64`/bilinmeyen RAM davranışı.
- `test_timeline_relations_reports.py`: Pydantic `ForensicArtifactModel`, UTC timeline/$\Delta t$, doğrulanmış/hipotez grafiği, HTML/PDF rapor üretimi.
- `test_tokens.py`, `test_ui_components.py`, `test_pages.py`: Açık/Koyu QSS tokenları, bileşenler ve 14 sayfanın headless Qt (`QT_QPA_PLATFORM=offscreen`) entegrasyonu.

## Çalıştırma
```powershell
python -m pytest -v
```
