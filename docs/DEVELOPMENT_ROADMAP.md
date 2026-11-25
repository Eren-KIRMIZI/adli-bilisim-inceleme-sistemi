# Development Roadmap

| Aşama | Modül / Kapsam | Durum |
|---|---|---|
| 1 | Proje iskeleti, PySide6 UI tasarım tokenları (Açık/Koyu), SQLite WAL altyapısı | Tamamlandı |
| 2 | Case Management (`case_engine` & `cases_page`) | Tamamlandı |
| 3 | Evidence Manager (`evidence_engine` & `evidence_page`) | Tamamlandı |
| 4 | Integrity & Chain of Custody (`QThread` SHA-256/512 & UNODC takip) | Tamamlandı |
| 5 | Windows Registry Engine (`regf` ikili kovan + `.lnk`, `.pf`, `$I` + canlı triage) | Tamamlandı |
| 6 | USB Forensics (`USBSTOR`, `MountedDevices`, anomali tespiti) | Tamamlandı |
| 7 | Windows Event Log Engine (`ElfFile` EVTX ayrıştırıcı) | Tamamlandı |
| 8 | File Analysis (imza, uzantı sahteciliği, entropi, EXIF, diff, duplicate) | Tamamlandı |
| 9 | Browser Forensics (Chrome, Edge, Firefox `?mode=ro` & maskeli çerezler) | Tamamlandı |
| 10 | NTFS & Disk Forensics (MBR/GPT, `$Boot`, `$MFT` silinmişler, File Carving, Hex) | Tamamlandı |
| 11 | Memory Forensics (`PAGEDU64/ELF/HIBR/LiME`, PE/IOC tarama & canlı süreçler) | Tamamlandı |
| 12 | Timeline Analysis (UTC birleştirme, yoğunluk grafiği, $\Delta t$) | Tamamlandı |
| 13 | Evidence Relations (NetworkX + etkileşimli grafik, kanıt/hipotez ayrımı) | Tamamlandı |
| 14 | Report Generator (Jinja2 HTML & ReportLab PDF, canlı önizleme) | Tamamlandı |
| 15 | Test (43 pytest), QSS görsel iyileştirme, WAL/elektrik kesintisi kurtarma | Tamamlandı |
| 16 | **DFIR Dalga 1 (P0)**: NTFS Data Runs/parçalı MFT/tam yol, `$UsnJrnl:$J`, `BinXml` EVTX, `db` Registry/UserAssist/ShimCache | Tamamlandı |
| 17 | **DFIR Dalga 2 (P1)**: Saf Python EnCase `.E01` EWF çözücü, 8 zamanlı Prefetch + OLE2 Jump List + ShellBags, KAPE-stili `TriageCollector` | Tamamlandı |
| 18 | **DFIR Dalga 3 (P2)**: Bellek KDBG/`Proc` pool heuristiği + Volatility 3 algılama, yerel SQLite Hash Set (NSRL/IOC) & YARA-stili tarayıcı (52 test) | Tamamlandı |
| 19 | **DFIR Dalga 4 (Genişletilmiş Modüller)**: BitLocker (`-FVE-FS-`), özyinelemeli `BagMRU` ShellBags + Amcache kovan çıkarımı, Super-Timeline çoklu artefakt birleştirme, çoklu modül HTML/PDF raporlama, NSRL/IOC içe aktarma & YARA klasör tarama, saf Python `.eml` (E-posta) ve `.pcap` / Hosts ağ ayrıştırıcıları (56 test) | Tamamlandı |

## İsteğe Bağlı İleri Modüller (Gelecek Eklentiler)
- E-posta PST/OST ikili kutusu ve SRUM (`SRUDB.dat`) ESE veritabanı ayrıştırıcısı
- Tam çekirdek PDB sembol sunucusu (DWARF/PDB) bellek çerçeve çözümlemesi
