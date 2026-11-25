# Adli Bilişim İnceleme Sistemi (`dijital-adli-bilisim`)

Windows sistemler, disk/RAM imajları ve dijital deliller üzerinde vaka yönetiminden muhafaza zincirine, düşük seviye ikili (binary) artefakt ayrıştırmadan olay korelasyonuna ve denetlenebilir adli raporlamaya kadar uçtan uca inceleme yapılmasını sağlayan **özgün, çevrimdışı ve salt-okunur Masaüstü Dijital Adli Bilişim (DFIR) Platformu**.

> Bu proje mevcut adli bilişim araçlarını (Autopsy, FTK, EnCase, The Sleuth Kit, Volatility, Plaso) saran bir arayüz **değildir**. NTFS/MFT, MBR/GPT, Windows Registry Hive (`regf`), Event Log (`ElfFile`), Prefetch, LNK, `$I` Geri Dönüşüm Kutusu, USBSTOR, EXIF, bellek dökümü ve tarayıcı SQLite motorları tamamen özgün olarak Python standart kütüphaneleriyle geliştirilmiştir.

---

## Temel İlkeler ve Uluslararası Standart Uyumluluğu

Uygulamanın iş akışı ve veri güvenilirliği kuralları uluslararası dijital adli bilişim standartları referans alınarak tasarlanmıştır:

| Standart / Rehber | Uygulamadaki Karşılığı |
|---|---|
| **NIST SP 800-86** | *Collection → Examination → Analysis → Reporting* dört aşamalı inceleme iş akışı, Windows artefakt ayrıştırma ve tekrarlanabilirlik. |
| **ISO/IEC 27037** | Orijinal delile sıfır müdahale, salt-okunur çalışma kopyası yaklaşımı ve donanımsal yazma engelleyici (write-blocker) kaydı. |
| **SWGDE (18-F-001)** | Raporlarda **objektif teknik bulgular** ile **uzman yorumu ve analiz sınırlamalarının** kesin biçimde birbirinden ayrılması. |
| **UNODC E4J Modül 6** | Eksiksiz **Muhafaza Zinciri (Chain of Custody)** takibi: teslim eden/alan, zaman damgası, konum, donanım ve **erişim amacı (purpose of access)**. |

### Adli Doğruluk ve Gizlilik Kuralları
- **Uydurma veya Tahmini Veri Üretilmez**: Desteklenmeyen RAM formatları, çözülemeyen sıkıştırılmış dosyalar veya kayıt defterinde bulunmayan zaman damgaları tahmin edilmez; açık uyarı veya eksik işaretiyle raporlanır.
- **Doğrulanmamış İlişki Ayrımı**: Bulgu İlişkilendirme grafiğinde doğrulanabilir kanıta dayanan bağlantılar **düz çizgi**, yalnızca zamansal yakınlığa dayanan hipotezler **kesik çizgi** ile gösterilir.
- **Hassas Veri Koruması**: Tarayıcı analizinde çerezlerin alan adı, ad ve zaman damgası metadata bilgileri çıkarılır; parola veya oturum belirteçleri (token) varsayılan olarak çıkarılmaz ve maskelenir.
- **Tamamen Çevrimdışı & Hafif**: Docker, WSL, container veya zorunlu bulut API gerektirmez; doğrudan Windows üzerinde çalışır.

---

## Dayanıklılık, Performans ve Elektrik Kesintisi Kurtarma (Fallback)

Kritik adli incelemeler sırasında yaşanabilecek ani elektrik kesintisi, sistem kilitlenmesi veya beklenmedik kapanmalara karşı uygulama çok katmanlı bir koruma mekanizmasıyla çalışır:

1. **SQLite WAL Modu + Tam Senkronizasyon (`src/database/models.py`)**:
   - Tüm veritabanı bağlantılarında `PRAGMA journal_mode=WAL;`, `PRAGMA synchronous=FULL;`, `PRAGMA foreign_keys=ON;` ve `PRAGMA busy_timeout=5000;` etkindir.
   - Yazma işlemleri Write-Ahead Log üzerinden atomik biçimde diske yazılır; ani güç kesintisinde veritabanı bozulması önlenir.
2. **Atomik Oturum Kontrol Noktası & Kesinti Kurtarma (`src/core/recovery.py`)**:
   - `RecoveryManager`, aktif vakayı, seçili delili, açık sayfayı, aktif temayı ve kaydedilmemiş rapor taslak notlarını 30 saniyede bir ve her önemli değişiklikte `.tmp` → `flush()` → `os.fsync()` → `os.replace()` sırasıyla atomik olarak `data/session_recovery.json` dosyasına yazar.
   - Uygulama açılışında `.session_active.lock` üzerinden önceki oturumun beklenmedik şekilde kapandığını tespit ederse çalışma durumunu otomatik geri yükler ve durum çubuğunda bilgilendirme gösterir.
3. **SHA-256 Doğrulamalı Çevrimiçi Yedekleme**:
   - Kapanışta `sqlite3.Connection.backup()` API'si ile WAL uyumlu tutarlı veritabanı yedeği ve yanında `.sha256` doğrulama dosyası üretilir (son 5 yedek korunur).
4. **Arayüzü Kilitlemeyen Arka Plan İşçileri (`QThread`)**:
   - Büyük disk/RAM imajlarının SHA-256 & SHA-512 hesaplamaları `HashWorker (QThread)` ile ilerleme çubuğu ve iptal desteğiyle arka planda yürütülür; tarayıcı SQLite veritabanları `?mode=ro` salt-okunur URI moduyla açılır.

---

## Modüller ve İşlevleri (14 Entegre Modül)

| # | Modül | Motor & Arayüz | Ne İşe Yarar? |
|---|---|---|---|
| **01** | **Genel Bakış (Dashboard)** | `dashboard_page.py` | Vaka/delil/artefakt sayıları, hash doğrulama özeti, son denetim günlüğü (Audit Trail), standart uyumluluk durumu ve hızlı geçiş butonları. |
| **02** | **Vaka Yönetimi (Cases)** | `case_engine/` | Benzersiz vaka numarasıyla soruşturma açma, durum geçişleri (`open`, `in_progress`, `closed`, `archived`), bağlı deliller ve vaka bazlı denetim geçmişi. |
| **03** | **Delil Yönetimi (Evidence)** | `evidence_engine/` | Cihaz/imaj envanteri, seri numarası, kapasite, yazma engelleyici (write-blocker) kaydı ve kabul anında tek geçişli SHA-256/SHA-512 hesaplama. |
| **04** | **Bütünlük & Muhafaza Zinciri** | `integrity_engine/` | Büyük dosyalar için `QThread` SHA-256/SHA-512 doğrulama, referans hash karşılaştırma ve UNODC uyumlu teslim/erişim amacı kayıtları (`ChainOfCustodyEntry`). |
| **05** | **Disk Forensics** | `ntfs_engine/` | Saf Python **EnCase `.E01` (EWF)** akış çözücü, **MBR & GPT**, **BitLocker (`-FVE-FS-`)** tespiti, **NTFS VBR & `$MFT`** (`data_runs` parçalı MFT akışı, tam dizin yolu çözümleme, aktif ve silinmiş kayıtlar, MACB, USA fixup), **`$UsnJrnl:$J`**, akış tabanlı **File Carving**; 3 sütunlu Finder düzeni + Hex görüntüleyici. |
| **06** | **Windows & Ağ Forensics** | `registry_engine/`, `eventlog_engine/`, `email_network_engine/` | Özgün **`regf` Registry Hive** (`db` Big Data, **UserAssist ROT13**, **ShimCache**, **`BagMRU` ShellBags**, **Amcache**), yapısal **`BinXml`** **`ElfFile` EVTX**, **`.lnk`**, 8 zamanlı **Prefetch (`.pf`)**, OLE2 **Jump List**, **`$I`**, **KAPE-stili `TriageCollector`** ve **`.pcap` / DNS / HTTP / `hosts`** ağ incelemesi. |
| **07** | **USB Cihaz Analizi** | `usb_engine/` | Canlı `winreg` (`USBSTOR`, `MountedDevices`) ve çevrimdışı `SYSTEM` kovanı analizi; VID/PID, seri no, sürücü harfi, kullanıcı ilişkisi ve şüpheli HID/BadUSB anomali tespiti. |
| **08** | **Tarayıcı Analizi** | `browser_engine/` | Chrome, Edge ve Firefox SQLite (`History`, `places.sqlite`, `Cookies`, `cookies.sqlite`, `Bookmarks`) veritabanlarından ziyaret, indirme, arama terimi ve maskeli çerez metadata çıkarımı (WebKit & PRTime → UTC). |
| **09** | **RAM Bellek Analizi** | `memory_engine/` | `PAGEDU64`, `PAGEDUMP`, `HIBR`, `ELF`, `LiME` başlığı doğrulama, **KDBG**, açık heuristik etiketli **`Proc` pool `EPROCESS` adayları**, bellek içi PE (`MZ/PE`) & IPv4/URL IOC taraması, opsiyonel Volatility 3 kontrolü ve canlı Toolhelp32 süreç görüntüsü. |
| **10** | **Dosya, YARA & E-posta** | `file_engine/`, `email_network_engine/` | Magic-byte dosya imzası & **uzantı sahteciliği**, Shannon entropisi, **JPEG EXIF**, yerel **SQLite Hash Set (NSRL/IOC CSV içe aktarma)**, saf Python **YARA-stili tekil/klasör tarayıcısı**, **RFC 5322 `.eml`** e-posta inceleme, diff ve duplicate taraması. |
| **11** | **Olay Zaman Çizelgesi** | `timeline_engine/` | USB, Muhafaza Zinciri, Denetim, DB `ForensicArtifact` ve `$MFT`/EVTX/Prefetch/Tarayıcı/E-posta artefaktlarını tek UTC **Super-Timeline**'da birleştirir; saatlik yoğunluk grafiği, filtreleme ve $\Delta t$ hesabı sunar. |
| **12** | **Bulgu İlişkilendirme** | `correlation_engine/` | NetworkX + etkileşimli `QGraphicsView` ile vaka-delil-kullanıcı-USB grafiği oluşturur; kanıtlı bağlantılar ile kanıtlanmamış zamansal hipotezleri net ayırır. |
| **13** | **Adli Rapor Oluşturucu** | `report_engine/` | Jinja2 ile **HTML** (canlı önizlemeli) ve ReportLab ile Türkçe font destekli **PDF** denetlenebilir adli inceleme raporu üretir (Çoklu Modül Artefakt/IOC bölümü dahil). |
| **14** | **Ayarlar & Lisanslar** | `settings_page.py` | Açık/Koyu tema seçimi, adli çalışma politikası özeti ve doğrulanmış açık kaynak bağımlılık lisans tablosu (`docs/LICENSES.md`). |

---

## Mimari ve Klasör Yapısı

```text
adli-bilisim-inceleme-sistemi/
├── main.py                         # Uygulama giriş noktası (Fusion stil + MainWindow)
├── requirements.txt                # Lisans kontrollü Python bağımlılıkları
├── pytest.ini                      # Test yapılandırması
├── docs/                           # Mimari, şema, güvenlik, test ve lisans belgeleri
├── src/
│   ├── core/                       # Standart Pydantic çıktı modeli ve crash recovery
│   ├── database/                   # SQLite WAL + SQLAlchemy ORM modelleri ve örnek vaka seed
│   ├── case_engine/                # Vaka yönetimi servisi
│   ├── evidence_engine/            # Delil envanteri ve kabul servisi
│   ├── integrity_engine/           # Çift katmanlı SHA-256/512 ve muhafaza zinciri
│   ├── ntfs_engine/                # MBR/GPT, NTFS VBR, $MFT ve File Carving motoru
│   ├── registry_engine/            # regf Hive, .lnk, .pf, $I ve canlı triage ayrıştırıcıları
│   ├── eventlog_engine/            # ElfFile EVTX ikili olay günlüğü ayrıştırıcısı
│   ├── usb_engine/                 # USBSTOR, MountedDevices ve anomali motoru
│   ├── browser_engine/             # Chrome, Edge ve Firefox salt-okunur ayrıştırıcı
│   ├── memory_engine/              # Bellek dökümü & Windows süreç snapshot motoru
│   ├── file_engine/                # İmza, EXIF, entropi, diff ve duplicate motoru
│   ├── timeline_engine/            # UTC birleşik zaman çizelgesi ve Δt hesaplayıcı
│   ├── correlation_engine/         # NetworkX bulgu ilişkilendirme motoru
│   ├── report_engine/              # Jinja2 HTML ve ReportLab PDF rapor üreticisi
│   └── ui/                         # PySide6 tasarım tokenları (Açık/Koyu), kabuk, bileşenler ve 14 sayfa
└── tests/                          # Sentetik ikili örnekler ve headless Qt test paketi (43 test)
```

---

## Kurulum, Çalıştırma ve Testler

### Gereksinimler
- **İşletim Sistemi**: Windows 10 / 11 (64-bit)
- **Python**: 3.11+ / 3.12+

### Kurulum ve Başlatma

```powershell
pip install -r requirements.txt
python main.py
```

Uygulama ilk açılışta `data/forensics.db` veritabanını WAL modunda oluşturur ve inceleme akışını hemen deneyebilmeniz için gerçekçi bir örnek soruşturma (`VAK-2026-084`) ile örnek USB/delil/muhafaza kayıtlarını yükler. Ayrıca **Disk Forensics**, **Windows Forensics**, **Browser Analysis**, **Memory Forensics** ve **File Analysis** sayfalarındaki `🧪 Örnek ...` butonlarıyla sentetik ikili (binary) adli örnekler üreterek ayrıştırıcıları çevrimdışı test edebilirsiniz.

### Otomatik Testleri Çalıştırma

```powershell
python -m pytest -v
```

Test paketi sentetik MBR/NTFS/$MFT/.E01/BitLocker imajları, `$UsnJrnl:$J`, `$SI`/`$FN` timestomping & ADS, `regf` Registry kovanları (UserAssist/ShimCache/ShellBags/Amcache), yapısal `BinXml` EVTX kayıtları, `.lnk`/8-TS `.pf`/Mini-Stream Jump List/`$I` dosyaları, `TriageCollector`, YARA/HashSet, `.eml` & `.pcap`/`hosts`, EXIF JPEG'ler, Chrome `visits`+WAL SQLite veritabanları, crash dump başlıkları + Volatility 3 köprüsü, `Super-Timeline` + CASE/UCO/JSONL/BodyFile + XSS korumalı HTML/PDF raporlama, hash zincirli `AuditLog`, WAL/kurtarma senaryoları, `100k` sayfalı tablo ölçek testi ve headless PySide6 arayüz/görsel bileşenlerini kapsayan **67 otomatik test** içerir.

---

## Dokümantasyon ve Lisanslar

- [Mimari Tasarım](docs/ARCHITECTURE.md)
- [Modül Tanımları](docs/MODULES.md)
- [Veritabanı Şeması](docs/DATABASE_SCHEMA.md)
- [Güvenlik ve Delil Bütünlüğü](docs/SECURITY.md)
- [Test Stratejisi](docs/TESTING.md)
- [Bağımlılık Lisansları](docs/LICENSES.md) (Yalnızca PSF, MIT, BSD, BSD-3-Clause ve LGPL-3.0 uyumlu paketler)
