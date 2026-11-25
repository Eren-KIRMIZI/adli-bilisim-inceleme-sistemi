# Adli Bilişim İnceleme Sistemi (`dijital-adli-bilisim`)

Windows sistemler, disk/RAM imajları ve dijital deliller üzerinde vaka yönetiminden muhafaza zincirine, düşük seviye ikili (binary) artefakt ayrıştırmadan olay korelasyonuna ve denetlenebilir adli raporlamaya kadar uçtan uca inceleme yapılmasını sağlayan **özgün, çevrimdışı ve salt-okunur Masaüstü Dijital Adli Bilişim (DFIR) Platformu**.

> Bu proje mevcut adli bilişim araçlarını (Autopsy, FTK, EnCase, The Sleuth Kit, Volatility, Plaso) saran bir arayüz **değildir**. NTFS/MFT, MBR/GPT, Windows Registry Hive (`regf`), Event Log (`ElfFile`), Prefetch, LNK, `$I` Geri Dönüşüm Kutusu, USBSTOR, EXIF, bellek dökümü ve tarayıcı SQLite motorları tamamen özgün olarak Python standart kütüphaneleriyle geliştirilmiştir.

---

## 🔐 USB Tabanlı Kriptografik Kimlik Doğrulama (Giriş Ekranı & 2FA)

Platformda klasik e-posta/kullanıcı adı girişi yerine adli bilişim laboratuvarlarına uygun **iki aşamalı donanım tabanlı kimlik doğrulama (2FA)** kapısı (`src/core/usb_auth_service.py` & `src/ui/pages/usb_login_window.py`) kullanılır:

### Nasıl Giriş Yapılır? (Adım Adım Akış)
1. **USB Güvenlik Anahtarı Beklenir (`WAITING_USB`):** Uygulama açıldığında çıkarılabilir USB sürücüleri gerçek zamanlı izlenir.
---


https://github.com/user-attachments/assets/07a73ba5-f65a-42e4-b00d-24e0be05194b


---

   ![USB Güvenlik Anahtarı Bekleniyor](docs/screenshots/00_usb_login_waiting.png)
2. **Canlı Ed25519 Challenge-Response İmza Doğrulaması (`1. Doğrulama`):** Kayıtlı USB bellek (ör. `Key D:`) takıldığında sistem yalnızca sürücü harfine veya kapasiteye bakmaz; her girişte **32 baytlık taze kriptografik rastgele challenge** üretir, USB üzerindeki `.forensic_key/usb_private_key.pem` (**Ed25519** özel anahtarı) ile imzalar ve sistemdeki açık anahtarla doğrular.
3. **Kişisel Güvenlik Şifresi (`2. Doğrulama`):** İmza doğrulandığında ekranda **`DİJİTAL İMZA DOĞRULANDI`** bildirimi açılır ve **PBKDF2-HMAC-SHA256 (200.000 iterasyon + salt)** ile korunan kişisel güvenlik şifresi istenir. 5 hatalı denemede geçici kilitleme (lockout) devreye girer ve tüm denemeler hash zincirli `AuditLog` tablosuna işlenir.
   ![Dijital İmza Doğrulandı ve Kişisel Şifre Ekranı](docs/screenshots/00b_usb_login_verified.png)
4. **Güvenli Oturum Başlatılır:** Her iki doğrulama da sağlandığında ana adli inceleme konsolu açılır; USB belleğin oturum öncesi çıkarılması durumunda şifre alanı otomatik olarak tekrar kilitlenir. *(İlk kez çalıştıranlar için kayıtlı anahtar yoksa sol alt köşedeki **İlk USB Anahtarı Kurulumu** sihirbazıyla kendi USB belleğinize Ed25519 anahtar çifti tanımlayabilirsiniz.)*

### 🎬 Giriş & Sistem Kullanım Videosu
> *Video Demo Alanı:* Buraya USB anahtarını takarak giriş yapma ve modül kullanım demosunu içeren videoyu ekleyebilirsiniz.
<!-- VIDEO_DEMO_PLACEHOLDER -->

---

## Gerçek Hayatta Ne Bulur ve Nasıl Kullanılır? (Örnek Olay Senaryosu)

Diyelim ki polis veya bir kurumsal olay müdahale (DFIR) uzmanı el koyulan veya teslim alınan şüpheli bir bilgisayarı inceliyor. Uzman şu temel sorulara teknik yanıt arar:

- Şüpheli bilgisayarda **hangi dosyaları oluşturmuş, değiştirmiş veya silmiş**?
- Bilgisayara **hangi USB bellekler** ne zaman bağlanmış?
- **Hangi internet sitelerine** girilmiş, **hangi dosyalar indirilmiş**?
- Hangi programlar çalıştırılmış, **olay günü adım adım neler yaşanmış**?
- Silinmiş dosyalardan hangileri kurtarılabilir?
- Başka cihazlar veya harici sunucularla (IP, URL, e-posta) bağlantı izi var mı?

### Örnek İnceleme Akışı — Vaka: `VAK-2026-084`

Uzman, şüpheli bilgisayarın salt-okunur disk imajını (`.E01` / `.dd`) veya toplanan çalışma kopyası paketini uygulamaya yüklediğinde modüller şu bulguları ortaya çıkarır:

#### 1. Disk İncelemesi (*Bilgisayarda neler yapılmış?*)
**Disk Forensics** modülü imajdaki MBR/GPT bölümlerini ve NTFS `$MFT` / `$UsnJrnl:$J` kayıtlarını tarayarak şunları listeler:
- **Aktif ve Silinmiş Dosyalar:** Belgeler, arşivler, görseller ve `$MFT` üzerinde hâlâ kurtarılabilir durumdaki silinmiş kayıtlar (`Unallocated`).
- **MACB Zaman Damgaları & Timestomping:** Oluşturma, değiştirme, erişim zamanları; ayrıca `$STANDARD_INFORMATION` ve `$FILE_NAME` zamanları arasındaki tutarsızlıklar (sahte tarih şüphesi).
- **Gizli Akışlar & Uzantı Sahteciliği:** NTFS Alternatif Veri Akışları (ör. indirme kaynağı `Zone.Identifier`) ve uzantısı `.jpg` gösterildiği halde gerçek dosya imzası (magic-byte) çalıştırılabilir EXE olan sahte dosyalar.
- **File Carving:** Dosya sistemi kaydı tamamen silinmiş ancak ham veri sektörlerinde kalan PDF, JPEG, ZIP veya SQLite kalıntıları.

#### 2. Tarayıcı İncelemesi (*İnternette neler yapılmış?*)
**Tarayıcı Analizi** modülü Chrome, Edge ve Firefox veritabanlarını (`?mode=ro` + `-wal`/`-shm` çalışma kopyası üzerinden) okur:
- `10:15` — Şüpheli bulut depolama / panel adresine ziyaret
- `10:32` — `arsiv.zip` veya çalıştırılabilir araç dosyasının indirilmesi
- `11:05` — Arama motorunda belirli anahtar kelimelerin aranması
- `11:40` — Silme / temizleme aracına dair sayfaların ziyareti

> *Adli Not:* Tarayıcı geçmişinde bir adresin bulunması tek başına kullanıcının niyetini veya eylemi bizzat yaptığını kanıtlamaz; diğer sistem izleriyle birlikte değerlendirilir.

> **Örnek Vaka Çalışması & Üretilen Gerçek Çıktılar:** Şüpheli bir bilgisayara ait disk, Registry, EVTX, Prefetch/LNK/Jump List, tarayıcı, RAM dökümü, YARA/uzantı sahteciliği ve ağ paketlerinin uçtan uca incelenerek HTML/PDF rapor, CASE/UCO JSON-LD, Timesketch JSONL ve Sleuth Kit BodyFile çıktılarının alındığı çalışma için [VAK-2026-084 İnceleme Raporu](docs/CASE_STUDY_VAK_2026_084.md) ve [outputs/vak_2026_084/](outputs/vak_2026_084/) klasörüne bakın (`python scripts\run_real_investigation.py`).

---

## Modül Ekran Görüntüleri ve Adli Tespit Örnekleri

### 01. Genel Bakış (Dashboard)
![Genel Bakış (Dashboard)](docs/screenshots/01_dashboard.png)

Tüm vaka metriklerini, canlı veritabanından hesaplanan kriptografik doğrulama yüzdesini (dairesel halka gösterge), adli denetim yoğunluğu eğrisini (`SplineAreaChart`) ve hash zincirli son sistem işlemlerini tek ekranda toplar.

### 02. Vaka Yönetimi (Cases)
![Vaka Yönetimi](docs/screenshots/02_cases.png)

Her adli soruşturmayı benzersiz vaka numarası (`VAK-2026-084`), sorumlu uzman, kurum ve durum geçişleriyle (`open`, `in_progress`, `closed`, `archived`) izler; delillerin silinmesi yerine adli arşivleme ilkesini uygular.

### 03. Delil Yönetimi (Evidence)
![Delil Yönetimi](docs/screenshots/03_evidence.png)

Teslim alınan fiziksel/mantıksal medya envanterini, seri numaralarını, kapasite bilgilerini, donanımsal yazma engelleyici (write-blocker) kullanım kaydını ve kabul anındaki SHA-256/SHA-512 özetlerini saklar.

### 04. Bütünlük & Muhafaza Zinciri (Integrity & Chain of Custody)
![Bütünlük ve Muhafaza Zinciri](docs/screenshots/04_integrity.png)

Büyük disk ve bellek imajlarının SHA-256 ve SHA-512 özetlerini arayüzü kilitlemeden (`QThread`) hesaplar, referans hash değeriyle karşılaştırarak `EŞLEŞTİ` / `UYUŞMAZLIK` durumunu UNODC uyumlu Muhafaza Zinciri kaydına işler.

### 05. Disk Forensics (MBR/GPT, NTFS/$MFT & File Carving)
![Disk Forensics](docs/screenshots/05_disk_forensics.png)

Saf Python `.E01` (EWF) / `.dd` okuyucusuyla bölüm tablosunu ve NTFS `$MFT` / `$UsnJrnl:$J` kayıtlarını ayrıştırır; `VAK-2026-084` incelemesinde aktif dosyaların yanında silinmiş `\Users\silinen_kanit.jpg` ve `\Users\silinen_betik.ps1` kayıtlarını ile ham sektör imzalarını çıkarmıştır.

### 06. Windows & Ağ Forensics (Registry, EVTX, Prefetch, LNK & PCAP)
![Windows Forensics](docs/screenshots/06_windows_forensics.png)

Çevrimdışı `regf` Registry kovanlarını, `BinXml` kodlu `.evtx` güvenlik olaylarını, 8 zamanlı Prefetch (`.pf`), `.lnk` / OLE2 Jump List ve `$I` Geri Dönüşüm Kutusu izlerini ayrıca `.pcap` ağ yakalamalarını tek çalışma alanında çözümler.

### 07. USB Cihaz Analizi (USBSTOR & HID/BadUSB Anomalileri)
![USB Cihaz Analizi](docs/screenshots/07_usb_analysis.png)

`USBSTOR` ve `MountedDevices` kayıtlarından bağlanan harici depolama aygıtlarının VID/PID, seri numarası, sürücü harfi ve kullanıcı SID bilgisini çıkarır; HID keystroke enjektörü / BadUSB gibi anormal aygıt sınıflarını şüpheli olarak işaretler.

### 08. Tarayıcı Analizi (Chrome / Edge / Firefox)
![Tarayıcı Analizi](docs/screenshots/08_browser_forensics.png)

Salt-okunur `?mode=ro` SQLite kopyaları üzerinden ziyaret geçmişi, indirmeler (`rclone-v1.68-windows-amd64.zip`), arama sorguları (`usb data exfiltration powershell`) ve yer imlerini UTC zaman damgasıyla çıkarırken hassas çerez değerlerini gizlilik gereği maskeler.

### 09. RAM Bellek Analizi (Memory Forensics)
![RAM Bellek Analizi](docs/screenshots/09_memory_forensics.png)

`PAGEDU64` / `HIBR` / `ELF` / `LiME` dökümlerinde `KDBG` adreslerini, bellek içi `MZ/PE` enjeksiyonlarını, `Proc` havuzu `EPROCESS` adaylarını (`beacon_svc.exe`), gömülü IP/URL IOC kalıntılarını ve canlı Windows süreçlerini analiz eder; kuruluysa Volatility 3 ile entegre çalışır.

### 10. Dosya, İmza, YARA & Hex İnceleme
![Dosya ve Hex İnceleme](docs/screenshots/10_file_analysis.png)

Magic-byte imza analiziyle `.jpg` görünümlü `tatil_fatura_ek.jpg` dosyasının aslında `PE Executable (EXE/DLL)` olduğunu (`4D 5A` MZ başlığı) tespit eder ve yerleşik YARA-stili kurallarla `PowerShell_EncodedCommand` + `rclone` veri sızdırma dizgelerini yakalar.

### 11. Olay Zaman Çizelgesi (Super-Timeline UTC)
![Olay Zaman Çizelgesi](docs/screenshots/11_timeline.png)

Disk (`$MFT`), USB, EVTX, Muhafaza Zinciri, Denetim ve YARA/RAM/Ağ bulgularını UTC saat diliminde birleştirerek saatlik aktivite yoğunluğu spline grafiği ve iki olay arası $\Delta t$ süre hesabı sunar.

### 12. Bulgu İlişkilendirme Grafiği (Correlation Graph)
![Bulgu İlişkilendirme](docs/screenshots/12_relations.png)

Vaka, deliller, kullanıcı hesapları ve USB/artefakt izleri arasındaki bağlantıları görselleştirir; doğrulanabilir kayıtlı kanıtları **düz çizgiyle**, yalnızca zamansal yakınlığa dayanan hipotezleri ise **kesik çizgiyle** açıkça ayırır.

### 13. Adli Rapor Oluşturucu (HTML, PDF & X.509 İmza)
![Adli Rapor Oluşturucu](docs/screenshots/13_reports.png)

Seçili vaka için delil SHA-256 özetlerini, muhafaza zincirini, USB/IOC bulgularını, uzman değerlendirmesini ve analiz sınırlamalarını içeren XSS korumalı HTML ve Türkçe karakter destekli PDF adli raporlarını canlı önizlemeyle üretir; **X.509 RSA-PSS-SHA256** ile kriptografik olarak imzalayıp bağımsız imza doğrulaması (`.sig.json`) yapar.

### 14. Saha İmaj Edinim (Acquisition)
![Saha İmaj Edinim](docs/screenshots/14_acquisition.png)

Canlı Windows mantıksal birimleri ve fiziksel disk hedeflerini (`\\.\PhysicalDriveN`) salt-okunur listeler; tek parça (`.dd`) veya bölünmüş (`.001/.002`) ham imaj alırken anlık SHA-256/SHA-512 hesaplar, geri-okuma doğrulaması (`post_verification_matched`) yapar ve donanımsal yazma engelleyici kaydıyla `.acquisition.json` manifesti üretir.

### 15. Mobil, Bulut & Tehdit Avı Merkezi (ALEAPP/iLEAPP, FTS5 & CFReDS)
![Mobil ve Bulut Artefaktları](docs/screenshots/15_mobile_cloud_hunt.png)

Android (`msgstore.db` WhatsApp, `mmssms.db` SMS, `calls`), iOS (`Manifest.db`, `sms.db`, ikili/XML `.plist`) ve Bulut Senkronizasyon/Denetim günlüklerini (Microsoft 365 / Entra ID JSON/CSV, OneDrive, Google Drive) tek tabloda birleştirerek mobil cihaz ve bulut eksenindeki sızma/iletişim izlerini çözümler.

![SQLite FTS5 Tam Metin Arama ve Analist Etiketleme](docs/screenshots/15b_fts_bookmarks.png)

**SQLite FTS5** tam metin indeksleme motoru vaka klasöründeki belge/log/XML/DOCX/SQLite metin kalıntılarını BM25 sıralamalı kesitlerle (`snippet`) milisaniyede arar; **Analist Bulgu Etiketleme (Bookmarks)** katmanı ise `Kanıt`, `Şüpheli`, `Kritik IOC` ve `Yanlış Pozitif` etiketleriyle işaretlenen bulguları doğrudan HTML/PDF bilirkişi raporuna taşır.

![CFReDS Doğrulama, Uzak Triyaj ve STIX 2.1](docs/screenshots/15c_cfreds_benchmark.png)

Dahili **CFReDS Tarzı Referans Doğrulama Paketi** tüm ayrıştırıcıların doğruluk oranını (`%100`) test eder; ayrıca Velociraptor/KAPE tarzı salt-okunur uzak uç nokta PowerShell toplama betiği (`.ps1`) ile **STIX 2.1 IOC Paketi** üretir.

### 16. Ayarlar, Kurumsal RBAC & Açık Kaynak Lisans Kaydı
![Ayarlar, RBAC ve Lisanslar](docs/screenshots/16_settings.png)

Sabit koyu laboratuvar arayüzü politikasını, **PBKDF2-HMAC-SHA256** korumalı çoklu kullanıcı/rol matrisini (**RBAC**: `Admin`, `LeadInvestigator`, `Analyst`, `Reviewer`), X.509 laboratuvar imza sertifikası parmak izini ve doğrulanmış açık kaynak kütüphane envanterini (`docs/LICENSES.md`) gösterir.

#### 3. USB Cihaz İncelemesi (*Hangi harici bellekler takılmış?*)
**USB Cihaz Analizi** modülü Windows Registry (`USBSTOR`, `MountedDevices`) kayıtlarından bağlanan aygıtları çıkarır:
- Üretici, model, **VID/PID** ve donanım seri numarası,
- Windows tarafından atanan sürücü harfi (ör. `E:`, `G:`),
- Kayıt defteri anahtarı son yazma zamanı ve ilişkili kullanıcı hesabı / SID,
- Seri numarası eksik veya HID enjektör (BadUSB) sınıfındaki şüpheli aygıt uyarıları.

#### 4. Windows Çalıştırma İzleri & Ağ / E-posta İncelemesi
- **Windows Forensics:** `UserAssist` (ROT13), `ShimCache`, `Amcache`, 8 çalıştırma zaman damgalı **Prefetch (`.pf`)**, `.lnk` kısayolları, **Jump List** ve `BagMRU` **ShellBags** ile hangi programların çalıştırıldığı ve hangi klasörlerin açıldığı görünür; `ElfFile`/`BinXml` EVTX motoruyla oturum açma/kapama (`4624/4625`), yeni süreç (`4688`), servis kurulumu (`7045`) ve log temizleme (`1102`) olayları incelenir.
- **E-posta & Ağ:** `.eml` mesajlarındaki aktarım zinciri (`Received`), `SPF/DKIM` başlıkları, gövde URL'leri ve ek hash'leri; `.pcap` yakalamalarında ise DNS sorguları ve HTTP IOC izleri ayrıştırılır.

#### 5. RAM Bellek İncelemesi (*Olay anında bellekte neler çalışıyordu?*)
Elinizde bir RAM dökümü (`PAGEDU64`, `hiberfil.sys`, `.raw`) varsa:
- Bellek içi PE/DLL başlıkları (`MZ/PE`), `KDBG` işaretçileri ve `Proc` pool adayları (açık heuristik etiketiyle),
- Bellek içinde kalan IPv4 adresleri ve `http://` / `https://` URL kalıntıları taranabilir; sistemde kuruluysa opsiyonel **Volatility 3** (`windows.pslist`, `netscan`, `cmdline`, `malfind`) eklentileri JSON çıktısıyla köprülenir.

> *Adli Not:* RAM imajı alınmamış kapalı bir sistemde geçmişte çalışıp kapanmış her program RAM üzerinden bulunamaz; bu durumlarda Prefetch, EVTX, ShimCache ve Amcache kayıtlarına başvurulur.

#### 6. Olay Zaman Çizelgesi (*Tüm parçaların tek kronolojide birleşmesi*)
**Super-Timeline** modülü tüm kaynaklardan gelen bulguları tek bir UTC zaman çizelgesinde birleştirir:

| Saat (UTC — Örnek) | Olay | Kaynak Artefakt |
|---|---|---|
| `09:12` | Harici USB bellek bağlandı | Registry `USBSTOR` / `MountedDevices` |
| `09:24` | Yeni dosya oluşturuldu (`export.zip`) | NTFS `$MFT` / `$UsnJrnl:$J` |
| `09:38` | Harici web sitesine erişildi ve indirme yapıldı | Tarayıcı `History` (`visits` + `urls`) |
| `09:41` | `powershell.exe` çalıştırıldı | Prefetch (`.pf`) & EVTX `4688` |
| `10:05` | Kaynak belge geri dönüşüme gönderildi / silindi | `$I` Geri Dönüşüm Kutusu & `$MFT` |
| `10:18` | USB bağlantısı kesildi | Sistem olayları / aygıt durumu |

*(Yukarıdaki tablo kullanım mantığını göstermek için hazırlanmış temsili bir örnektir; gerçek incelemelerde her bulgu yalnızca doğrulanabilen ham kaynak kaydıyla raporlanır.)*

#### 7. Sonuç — Denetlenebilir Adli Bilişim Raporu & Birlikte Çalışabilirlik
Uzman inceleme sonunda vaka envanterini, SHA-256/512 doğrulama durumunu, hash zincirli muhafaza kayıtlarını, tespit edilen tüm bulguları, ilişki grafiğini (kanıt vs. hipotez ayrımıyla), uzman yorumunu ve analiz sınırlamalarını içeren **HTML / PDF** adli rapor oluşturabilir; ayrıca **CASE/UCO JSON-LD**, **Timesketch JSONL** ve **Sleuth Kit BodyFile** çıktısı alabilir.

### Proje Hedefi ve Yol Haritası İlkeleri
Bu proje Autopsy, FTK ve Magnet AXIOM ile aynı problem alanında çalışan, özgün analiz motorlarına sahip bir masaüstü DFIR platformu olarak geliştirilmektedir. Her bulgunun yalnızca *"şu dosya bulundu"* demesi yerine **hangi ham kayıttan çıktığını, ne kadar güvenilir olduğunu ve inceleme sınırlamalarını** şeffaf biçimde göstermesi hedeflenir:
- **Çapraz Bulgu Korelasyonu:** Aynı dosyaya ait `$MFT`, Prefetch ve EVTX kayıtlarını bir arada değerlendirmek,
- **Bağlamsal Teknik Eşleştirme:** Bulguları kanıt/suçlama iddiası sunmadan teknik sınıflandırma (ör. MITRE ATT&CK teknik bağlamı) ile ilişkilendirmek,
- **Delil Güvenilirlik Değerlendirmesi:** Her bulguda kaynak yolunu, parser sürümünü, hash bütünlüğünü ve laboratuvar referans doğrulama sınırlarını açıkça belirtmek.

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

## v2.0 & v3.0 Kurumsal, Saha & Tam DFIR Kapsam Katmanları

Başlangıçta yol haritasında yer alan kurumsal, saha ve gelişmiş DFIR yeteneklerinin tamamı projeye entegre edilmiştir:

- **Saha İmaj & Canlı Süreç Bellek Edinimi (`src/acquisition_engine/`):** Canlı Windows sürücülerini ve `\\.\PhysicalDriveN` aygıtlarını salt-okunur listeler, bölünmüş/tek parça RAW (`.dd` / `.001`) imaj alır, tek geçişli SHA-256/SHA-512 hesaplayıp geri-okuma ile doğrular; ayrıca Windows `dbghelp.dll!MiniDumpWriteDump` üzerinden hedef PID süreç bellek dökümü (`.dmp`) ve opsiyonel WinPMEM köprüsü sunar.
- **Genişletilmiş Disk Kapları & Dosya Sistemleri (`src/ntfs_engine/`):** `.dd`/`.E01` yanında **`.VHD`**, **`.VHDX`**, **`.QCOW2`**, **`.VMDK`**, **`.AFF4`** ve mantıksal **`.AD1`/`.L01`** kaplarını okur; **NTFS**, **FAT32**, **exFAT**, **Linux `ext4`** ve **Apple `APFS` (`NXSB`/`APSB`)** dosya sistemlerini, **VSS** gölge kopyalarını, NTFS **`$LogFile`** (`RSTR`/`RCRD`) işlemlerini ve **BitLocker (`-FVE-FS-`)** FVEK/kurtarma anahtarıyla sektör şifre çözmeyi destekler.
- **SRUM, BAM/DAM, `ActivitiesCache.db`, Scheduled Tasks, WMI & Sigma (`src/registry_engine/`, `src/eventlog_engine/`):** Saf Python **ESE/JET Blue** motoruyla `SRUDB.dat` (SRUM ağ/uygulama kullanımı), `BAM`/`DAM`, Windows 10/11 Timeline `ActivitiesCache.db`, Task XML, WMI `OBJECTS.DATA` ve EVTX üzerinde **Sigma YAML** tehdit avcılığı kural motorunu çalıştırır.
- **Gerçek YARA, `.pcapng`, `.mbox`/`.pst`, Mobil/Bulut, FTS5 & STIX 2.1:** `yara-python` ile harici `.yar` kuralları, PCAPNG (`.pcapng`), Outlook PFF (`.pst`/`.ost`) & `.mbox`, Android/iOS (WhatsApp `msgstore.db`, SMS, `Manifest.db`, `.plist`), M365/OneDrive bulut denetim günlükleri, **SQLite FTS5** tam metin arama, **Analist Bulgu Etiketleme (`ArtifactBookmark`)**, **STIX 2.1 / CSV** dışa aktarım, Velociraptor/KAPE tarzı uzak triyaj `.ps1` üreticisi ve **CFReDS doğrulama paketi** entegredir.
- **Canlı İşletim Sistemi Yetki & UAC Yönetimi (`src/core/privilege_service.py`):** Standart kullanıcı oturumunda kilitli olan `System.evtx` / `Security.evtx` ve `C:\Windows\Prefetch` erişim durumunu dürüstçe raporlar; kullanıcının açık onayıyla resmi Windows UAC (`runas`) yükseltmesi başlatabilir.
- **Gelişmiş RAM Çekirdek Başlığı & Volatility 3 Köprüsü (`src/memory_engine/`):** `PAGEDU64` (`DUMP_HEADER64`) içerisinden `DirectoryTableBase (CR3)`, `PsLoadedModuleList`, `PsActiveProcessHead`, çekirdek sayısı ve `BugCheckCode` alanlarını çözümler; opsiyonel **Volatility 3** kurulu ortamlarda `-r json` eklenti köprüsünü çalıştırır.
- **Kurumsal Çoklu Kullanıcı (RBAC) & X.509 Rapor İmzalama (`src/core/auth_service.py`, `src/core/signing_service.py`):** `PBKDF2-HMAC-SHA256` (200.000 iterasyon + salt) parola doğrulamasıyla `Admin`, `LeadInvestigator`, `Analyst` ve `Reviewer` rollerini ayırır; HTML/PDF raporları **X.509 RSA-2048 RSA-PSS-SHA256** sertifikasıyla imzalayıp 1 baytlık değişikliği bile yakalayan bağımsız imza doğrulaması sunar.

---

## Modüller ve İşlevleri (16 Entegre Modül)

| # | Modül | Motor & Arayüz | Ne İşe Yarar? |
|---|---|---|---|
| **01** | **Genel Bakış (Dashboard)** | `dashboard_page.py` | Vaka/delil/artefakt sayıları, hash doğrulama özeti, son denetim günlüğü (Audit Trail), standart uyumluluk durumu ve hızlı geçiş butonları. |
| **02** | **Vaka Yönetimi (Cases)** | `case_engine/` | Benzersiz vaka numarasıyla soruşturma açma, durum geçişleri (`open`, `in_progress`, `closed`, `archived`), bağlı deliller ve vaka bazlı denetim geçmişi. |
| **03** | **Delil Yönetimi (Evidence)** | `evidence_engine/` | Cihaz/imaj envanteri, seri numarası, kapasite, yazma engelleyici (write-blocker) kaydı ve kabul anında tek geçişli SHA-256/SHA-512 hesaplama. |
| **04** | **Bütünlük & Muhafaza Zinciri** | `integrity_engine/` | Büyük dosyalar için `QThread` SHA-256/SHA-512 doğrulama, referans hash karşılaştırma ve UNODC uyumlu teslim/erişim amacı kayıtları (`ChainOfCustodyEntry`). |
| **05** | **Disk Forensics** | `ntfs_engine/` | Saf Python `.E01`/`.dd`/`.VHD`/`.VHDX`/`.QCOW2`/`.VMDK`/`.AFF4`/`.AD1`/`.L01`, **NTFS/FAT32/exFAT/ext4/APFS**, **BitLocker (`-FVE-FS-`)** FVEK çözme, **VSS**, **`$LogFile`**, **`$UsnJrnl:$J`**, File Carving + Hex görüntüleyici. |
| **06** | **Windows & Ağ Forensics** | `registry_engine/`, `eventlog_engine/`, `email_network_engine/` | Özgün **`regf` Registry Hive** (UserAssist, ShimCache, ShellBags, Amcache, **BAM/DAM**), **`SRUDB.dat` (ESE/SRUM)**, **`ActivitiesCache.db`**, Task XML, WMI `OBJECTS.DATA`, **`BinXml` EVTX + Sigma YAML**, `.lnk`/`.pf`/Jump List/`$I`, **`.pcap`/`.pcapng`/DNS/HTTP/`hosts`**. |
| **07** | **USB Cihaz Analizi** | `usb_engine/` | Canlı `winreg` (`USBSTOR`, `MountedDevices`) ve çevrimdışı `SYSTEM` kovanı analizi; VID/PID, seri no, sürücü harfi, kullanıcı ilişkisi ve şüpheli HID/BadUSB anomali tespiti. |
| **08** | **Tarayıcı Analizi** | `browser_engine/` | Chrome, Edge ve Firefox SQLite (`History`, `places.sqlite`, `Cookies`, `cookies.sqlite`, `Bookmarks`) veritabanlarından ziyaret, indirme, arama terimi ve maskeli çerez metadata çıkarımı (WebKit & PRTime → UTC). |
| **09** | **RAM Bellek Analizi** | `memory_engine/` | `PAGEDU64`, `PAGEDUMP`, `HIBR`, `ELF`, `LiME` başlığı doğrulama, **KDBG**, açık heuristik etiketli **`Proc` pool `EPROCESS` adayları**, bellek içi PE (`MZ/PE`) & IPv4/URL IOC taraması, opsiyonel Volatility 3 kontrolü ve canlı Toolhelp32 süreç görüntüsü. |
| **10** | **Dosya, YARA & E-posta** | `file_engine/`, `email_network_engine/` | Magic-byte dosya imzası & uzantı sahteciliği, Shannon entropisi, EXIF, yerel Hash Set (NSRL/IOC), **`yara-python` (.yar) + Python YARA**, **`.eml` / `.mbox` / `.pst`/`.ost` (PFF)** inceleme, diff ve duplicate taraması. |
| **11** | **Olay Zaman Çizelgesi** | `timeline_engine/` | USB, Muhafaza Zinciri, Denetim, DB `ForensicArtifact` ve `$MFT`/EVTX/Prefetch/Tarayıcı/E-posta artefaktlarını tek UTC **Super-Timeline**'da birleştirir; saatlik yoğunluk grafiği, filtreleme ve $\Delta t$ hesabı sunar. |
| **12** | **Bulgu İlişkilendirme** | `correlation_engine/` | NetworkX + etkileşimli `QGraphicsView` ile vaka-delil-kullanıcı-USB grafiği oluşturur; kanıtlı bağlantılar ile kanıtlanmamış zamansal hipotezleri net ayırır. |
| **13** | **Adli Rapor Oluşturucu** | `report_engine/`, `signing_service.py` | Jinja2 HTML, ReportLab PDF (analist bookmarkları dahil), **X.509 RSA-PSS-SHA256** imza ve **STIX 2.1 / CSV / CASE-UCO** dışa aktarımı. |
| **14** | **Saha İmaj Edinim** | `acquisition_engine/` | Mantıksal/fiziksel disklerden salt-okunur RAW (`.dd`/`.001`) imaj edinimi, SHA-256/512 geri-okuma doğrulaması ve canlı süreç **PID `MiniDumpWriteDump`** bellek dökümü. |
| **15** | **Mobil, Bulut & Tehdit Avı** | `mobile_cloud_engine/`, `fts_index.py`, `bookmark_service.py` | Android/iOS (WhatsApp/SMS/iMessage/`Manifest.db`/`.plist`), M365/OneDrive bulut denetimi, **SQLite FTS5** tam metin arama, bulgu etiketleme, uzak triyaj `.ps1` ve **CFReDS doğrulama paketi**. |
| **16** | **Ayarlar, RBAC & Lisanslar** | `settings_page.py`, `auth_service.py` | Sabit koyu konsol ilkeleri, PBKDF2-HMAC-SHA256 çoklu kullanıcı RBAC matrisi, X.509 sertifika parmak izi ve lisans kaydı. |

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
│   ├── acquisition_engine/         # Salt-okunur RAW (.dd/.001) & PID MiniDump edinim motoru
│   ├── mobile_cloud_engine/        # Android/iOS (WhatsApp/SMS/Plist) & M365/OneDrive bulut motoru
│   └── ui/                         # PySide6 koyu konsol teması (tokens.py), kabuk, QPainter grafikler ve 16 sayfa
└── tests/                          # Sentetik ikili örnekler, RBAC/X.509, USB 2FA, v3.0 DFIR ve headless Qt testleri (78 test)
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

Test paketi sentetik MBR/NTFS/$MFT/.E01/VHD/VHDX/QCOW2/AFF4/AD1/FAT32/exFAT/ext4/APFS/BitLocker FVEK imajları, `$UsnJrnl:$J`, `$LogFile`, VSS, `$SI`/`$FN` timestomping & ADS, `regf` Registry kovanları (UserAssist/ShimCache/ShellBags/Amcache/BAM), ESE/`SRUDB.dat`, `ActivitiesCache.db`, Task XML, WMI `OBJECTS.DATA`, yapısal `BinXml` EVTX + Sigma YAML kuralları, `.lnk`/8-TS `.pf`/Mini-Stream Jump List/`$I` dosyaları, `TriageCollector` + uzak `.ps1`, YARA (`yara-python`/Python)/HashSet, `.eml`/`.mbox`/`.pst` & `.pcap`/`.pcapng`/`hosts`, WhatsApp/iOS/M365, SQLite FTS5, `ArtifactBookmark`, EXIF JPEG'ler, Chrome `visits`+WAL SQLite veritabanları, `DUMP_HEADER64` (`CR3`) + Volatility 3 köprüsü, `Super-Timeline` + CASE/UCO/STIX 2.1/CSV/JSONL/BodyFile + XSS korumalı HTML/PDF + **X.509 RSA-PSS-SHA256 rapor imzalama**, **PBKDF2 RBAC yetkilendirme**, **RAW/bölünmüş & PID MiniDump saha edinimi**, hash zincirli `AuditLog`, WAL/kurtarma senaryoları, `100k` sayfalı tablo ölçek testi ve headless PySide6 arayüz/grafik bileşenlerini kapsayan **78 otomatik test** içerir.

Gerçek bir Windows 11 iş istasyonunda salt-okunur çalıştırılan çapraz doğrulama sonuçları (`Get-FileHash`, canlı `winreg`, `USBSTOR`, gerçek `.lnk`/OLE2 Jump List, Microsoft Edge profili ve Toolhelp32 süreçleri) için: [scripts/verify_real_world.py](scripts/verify_real_world.py) ve [Gerçek Dünya Doğrulama Raporu](docs/REAL_WORLD_VALIDATION.md).

---

## Dokümantasyon ve Lisanslar

- [Mimari Tasarım](docs/ARCHITECTURE.md)
- [Modül Tanımları](docs/MODULES.md)
- [Veritabanı Şeması](docs/DATABASE_SCHEMA.md)
- [Güvenlik ve Delil Bütünlüğü](docs/SECURITY.md)
- [Test Stratejisi](docs/TESTING.md)
- [Örnek Vaka Çalışması (VAK-2026-084)](docs/CASE_STUDY_VAK_2026_084.md)
- [Gerçek Dünya Doğrulama Raporu](docs/REAL_WORLD_VALIDATION.md)
- [Bağımlılık Lisansları](docs/LICENSES.md) (Yalnızca PSF, MIT, BSD, BSD-3-Clause ve LGPL-3.0 uyumlu paketler)
