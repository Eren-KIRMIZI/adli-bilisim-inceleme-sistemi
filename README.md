# Adli Bilişim İnceleme Sistemi (Digital Forensics Suite)

Windows bilgisayarların adli bilişim incelemeleri için tamamen özgün, modüler, salt-okunur ve çevrimdışı çalışan masaüstü dijital adli bilişim (DFIR) uygulaması.

## Özellikler ve Modüller

1. **Dashboard**: Vaka özeti, delil envanteri, hash doğrulama metrikleri ve denetim günlüğü (Audit Trail).
2. **Case Management (`case_engine`)**: Soruşturma açma, durum yönetimi, bağlı deliller ve vaka analiz geçmişi.
3. **Evidence Manager (`evidence_engine`)**: Donanım/imaj kabulü, yazma engelleyici (write-blocker) kaydı, otomatik SHA-256/SHA-512 hesaplama.
4. **Integrity & Chain of Custody (`integrity_engine`)**: `QThread` destekli büyük dosya SHA-256/SHA-512 doğrulama ve muhafaza zinciri takibi.
5. **Disk Forensics (`ntfs_engine`)**: Özgün MBR/GPT bölüm tablosu, NTFS VBR/`$MFT` (aktif ve silinmiş kayıtlar), imza tanıma ve File Carving motoru; 3 sütunlu gezgin + alt Hexadecimal görüntüleyici.
6. **Windows Forensics (`registry_engine`, `eventlog_engine`)**: Özgün `regf` Registry Hive ağacı, `ElfFile` EVTX olay günlüğü, `.lnk` Shell Link, `.pf` Prefetch, `$I` Geri Dönüşüm Kutusu ayrıştırıcıları ve canlı Windows triage.
7. **USB Analysis (`usb_engine`)**: `USBSTOR` / `MountedDevices` / canlı kayıt defteri analizi, VID/PID/Seri ve şüpheli cihaz tespiti.
8. **Browser Forensics (`browser_engine`)**: Chrome, Edge ve Firefox SQLite (`?mode=ro`) ziyaret/indirme/arama/yer imi ve maskeli çerez metadata analizi.
9. **Memory Forensics (`memory_engine`)**: RAM döküm başlıkları (`PAGEDU64`, `ELF`, `HIBR`, `LiME`), KDBG/PE modül ve IOC taraması, canlı Windows süreç anlık görüntüsü.
10. **File Analysis (`file_engine`)**: Magic-byte imza & uzantı sahteciliği tespiti, Shannon entropisi, JPEG EXIF ayrıştırıcı, dosya karşılaştırma (Diff) ve yinelenen dosya taraması.
11. **Timeline Analysis (`timeline_engine`)**: Tüm kaynaklardan UTC zaman çizelgesi birleştirme, yoğunluk grafiği ve olaylar arası zaman farkı ($\Delta t$) hesabı.
12. **Evidence Relations (`correlation_engine`)**: NetworkX tabanlı interaktif bulgu ilişki grafiği; kanıtlı ilişkiler ile kanıtlanmamış zamansal hipotezlerin kesin ayrımı.
13. **Report Generator (`report_engine`)**: Jinja2 HTML ve ReportLab PDF formatında denetlenebilir adli raporlar ve canlı önizleme.
14. **Settings & Licenses**: Açık/Koyu tema seçimi ve doğrulanmış açık kaynak lisans kaydı (`docs/LICENSES.md`).

## Kurulum ve Çalıştırma

```powershell
pip install -r requirements.txt
python main.py
```

## Otomatik Testler

```powershell
python -m pytest -v
```
