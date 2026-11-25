# Testing

Her analiz motoru, veri katmanı, kurtarma mekanizması ve arayüz bileşeni otomatik testlere sahiptir. Testlerde gerçek kişilere ait veriler yerine kod içinde üretilen sentetik ikili (binary) ve SQLite adli örnekler kullanılır.

## Test Kapsamı (`tests/` — 66 Test)
- `test_scale_orchestrator_vol3.py`: 100.000 satırlı sayfalı `ForensicDataTable` / `ForensicTableModel`, `PluginRegistry` & `AnalysisOrchestrator` çoklu motor ingest kuyruğu, **CASE/UCO JSON-LD**, **Timesketch JSONL**, **BodyFile** dışa aktarımları, RAM tarama sınırı uyarısı ve Volatility 3 JSON köprüsü.
- `test_audit_fixes.py`: Write-Blocker `False` varsayılanı, katı SHA-256 doğrulama ayrımı, hash zincirli append-only denetim kaydı ve arşivleme, HTML XSS & PDF XML escaping, `StatusBadge` eşleştirme, dürüst USB offline hive ayrıştırma, OLE2 Jump List MS-CFB Mini-Stream (`<4096 B`), NTFS `$SI` vs `$FN` timestomping & ADS ve Tarayıcı `visits` birleştirme/kesme uyarıları.
- `test_case_evidence_integrity.py`: Vaka yaşam döngüsü, delil kabulü, muhafaza zinciri ve SHA-256/512 doğrulama.
- `test_database.py`: SQLite şema oluşturma ve sentetik vaka seed doğrulaması.
- `test_recovery.py`: SQLite WAL modu, beklenmedik elektrik kesintisi/çökme kurtarma ve `.sha256` yedek doğrulaması.
- `test_disk_and_ntfs.py`: Sentetik MBR, GPT, NTFS VBR, `$MFT` (aktif/silinmiş), File Carving ve E01 uyarı davranışı.
- `test_windows_forensics.py`: Sentetik `regf` Registry Hive, `ElfFile` EVTX, `.lnk`, `.pf`, `$I` ayrıştırma ve bozuk dosya hata davranışı.
- `test_wave1_p0.py`: NTFS `data_runs`/parçalı `$MFT`/tam yol çözümleme, `$UsnJrnl:$J` (V2/V3) & streaming carving, yapısal `BinXml` EVTX, UserAssist ROT13 & ShimCache testleri.
- `test_wave2_wave3_p1_p2.py`: Saf Python `.E01` (EWF) sıkıştırma çözme ve uçtan uca NTFS incelemesi, 8 zamanlı Prefetch + Jump List + ShellBags, `TriageCollector` SHA-256 manifesti, bellek `Proc` pool heuristiği, `HashSetService`, `YaraStyleScanner` ve UI doğrulaması.
- `test_wave4_dfir_extensions.py`: BitLocker `-FVE-FS-` tespiti, özyinelemeli `BagMRU` ShellBags çıkarımı, çoklu modül `Super-Timeline` & HTML/PDF raporlama, `.eml` / `.pcap` / `hosts` ayrıştırma, HashSet CSV içe aktarma ve YARA klasör tarama UI doğrulaması.
- `test_usb_service.py`: USBSTOR kayıtları, string ayrıştırma ve şüpheli cihaz işaretleme.
- `test_file_browser_memory.py`: EXIF JPEG, uzantı sahteciliği, diff/duplicate, Chrome SQLite/maskeli çerezler ve `PAGEDU64`/bilinmeyen RAM davranışı.
- `test_timeline_relations_reports.py`: Pydantic `ForensicArtifactModel`, UTC timeline/$\Delta t$, doğrulanmış/hipotez grafiği, HTML/PDF rapor üretimi.
- `test_tokens.py`, `test_ui_components.py`, `test_pages.py`: Açık/Koyu QSS tokenları, bileşenler ve 14 sayfanın headless Qt (`QT_QPA_PLATFORM=offscreen`) entegrasyonu.

## Çalıştırma
```powershell
python -m pytest -v
```
