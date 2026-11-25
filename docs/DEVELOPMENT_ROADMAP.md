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
| 20 | **Adli Güvenilirlik, Güvenlik & Performans Sertleştirme**: Write-Blocker `False` varsayılanı, katı hash doğrulama ayrımı, hash zincirli append-only `AuditLog` + `archive_case`, Jinja2 autoescape + PDF escaping (XSS koruması), dürüst `UsbService`, `StatusBadge` tam token eşleştirme, tek geçişli streaming hash (`FileAnalysisService`), taşınabilir `mbcs` fallback, MS-CFB Mini-Stream Jump List, NTFS `$SI`/`$FN` timestomping + ADS + EWF Adler-32 sağlama, `visits` + WAL tarayıcı okuması, `QThread` arka plan çalışanları (`EvidencePage`/`DiskForensicsPage`) ve WCAG AA kontrast güncellemesi (63 test) | Tamamlandı |
| 21 | **Ölçek, Orkestrasyon & Birlikte Çalışabilirlik**: Sayfalı `ForensicDataTable` + `ForensicTableModel` (`100k+` satır), bellek dostu MFT önizleme, `PluginRegistry` + `AnalysisOrchestrator` + arka plan ingest kuyruğu, **CASE/UCO JSON-LD**, **Timesketch JSONL** ve **Sleuth Kit BodyFile** dışa aktarımı, Volatility 3 JSON köprüsü (`pslist`/`pstree`/`netscan`/`cmdline`/`malfind`) + `mmap` kesme uyarısı, canlı DB KPI kartları, `pyproject.toml` ve `.github/workflows/ci.yml` (66 test) | Tamamlandı |
| 22 | **Görsel Marka & SVG Kabuk İyileştirmesi**: Gemini Banana (`brand_shield.png`, `lab_banner_light.png`, `lab_banner_dark.png`) uygulama ikonu ve Dashboard laboratuvar şeridi, `QSvgRenderer` vektör yan menü ikonları ve daraltılabilir `Sidebar` (67 test) | Tamamlandı |
| 23 | **v2.0 Kurumsal & Saha Katmanları**: RAW/bölünmüş saha imaj edinimi (`acquisition_engine`), UAC yükseltme (`privilege_service`), PBKDF2 RBAC (`auth_service`), X.509 RSA-PSS rapor imzalama (`signing_service`) ve `DUMP_HEADER64` `CR3` (72 test) | Tamamlandı |
| 24 | **v3.0 Tam DFIR Kapsam Genişlemesi**: FAT32/exFAT/ext4/APFS, VHD/VHDX/QCOW2/VMDK/AFF4/AD1/L01, BitLocker FVEK çözme, VSS & `$LogFile`, ESE/`SRUDB.dat` (SRUM), BAM/DAM, `ActivitiesCache.db`, Task XML, WMI `OBJECTS.DATA`, Sigma YAML EVTX avcılığı, `yara-python`, `.pcapng`, `.mbox`/`.pst`, Android/iOS/M365 (`mobile_cloud_engine`), SQLite FTS5, `ArtifactBookmark`, STIX 2.1/CSV, PID `MiniDumpWriteDump`, uzak triyaj `.ps1` ve CFReDS referans doğrulama paketi (76 test) | Tamamlandı |
