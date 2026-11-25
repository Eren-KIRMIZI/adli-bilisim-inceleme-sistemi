# Gerçek Dünya Doğrulama Raporu (Windows 11 Read-Only DFIR Validation)

Bu belge, uygulamanın sentetik testlere ek olarak **gerçek bir Windows 11 iş istasyonu üzerinde** tamamen **salt okunur (read-only)** çalıştırılan [verify_real_world.py](../scripts/verify_real_world.py) doğrulama betiği çıktısını ve tespit edilen erişim/yetki sınırlarını kayıt altına alır.

## Çalıştırma Ortamı
- **Tarih / Saat (UTC):** `2026-11-25T14:05:17Z`
- **İşletim Sistemi / Mimari:** Windows (`nt`), Python `3.11.9`
- **Çalıştırma Komutu:** `python scripts\verify_real_world.py`
- **Güvenlik İlkesi:** Betik canlı sistem dosyalarına, kayıt defterine veya tarayıcı SQLite veritabanlarına yazma yapmaz; tarayıcı/SQLite dosyalarını salt okunur (`WAL` / `-shm` sidecar güvenli kopyalama) yöntemle okur.

## Gözlemlenen Sonuçlar ve Çapraz Doğrulama

| Modül / Kontrol | Karşılaştırma / Kaynak | Sonuç | Detaylar |
|---|---|---|---|
| **SHA-256 Bütünlük Doğrulama** | PowerShell `Get-FileHash` vs `IntegrityService` & `FileService` | **Birebir Eşleşti (`matched: true`)** | `bab0b539d0e38899d95973fcfc2da62ef5c96ceb8427ecb97c194e73f569bbe8` |
| **Canlı Registry Triage (`winreg`)** | `LiveTriageService` (`HKLM` / `HKCU`) | **Doğrulandı (`supported: true`)** | Run/RunOnce: `5`, Windows Servisleri: `131`, ProfileList: `4`, TypedPaths: `5`, UserAssist (ROT13): `129`, ShimCache: `150` |
| **Canlı USBSTOR Doğrulama** | `HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR` | **Doğrulandı (`1` Cihaz)** | `Kingston DataTraveler 3.0` (`Serial: E0D55EA57410E9B159D80011&0`). Mevcut olmayan sürücü harfi (`drive: null`) ve kayıt defteri zaman damgası (`ts_honest_none: true`) uydurulmadan `None` bırakıldı. |
| **Gerçek `.lnk` Kısayol Dosyaları** | `%APPDATA%\Microsoft\Windows\Recent\*.lnk` | **`15 / 15` Başarılı** | `0` ayrıştırma hatası. |
| **Gerçek OLE2 Jump List (`.automaticDestinations-ms`)** | `%APPDATA%\Microsoft\Windows\Recent\AutomaticDestinations` | **`10 / 10` Başarılı** | MS-CFB Mini-Stream ayrıştırıcısı ile `200` dahili LNK akışı (`0` hata) çıkarıldı. |
| **Gerçek Tarayıcı Geçmişi & İndirmeler** | `%LOCALAPPDATA%\Microsoft\Edge\User Data\Default` | **Doğrulandı (`1` Profil)** | `history: 500` (kesme uyarısı aktif), `downloads: 15`, `searches: 354`, `bookmarks: 1`. `500` kayıt sınırına ulaşıldığında kullanıcıya açık uyarı üretildi. |
| **Canlı Bellek Süreçleri & Ağ Bağlantıları** | Win32 `CreateToolhelp32Snapshot`, `hosts`, `netstat` | **Doğrulandı** | `226` aktif süreç, `30` örneklenen `netstat` TCP/UDP bağlantısı. |

## Dürüst Kapsam ve Yetki Sınırlamaları (Yönetici Olmayan Oturumda Gözlenen)
Gerçek dünya testleri, aracın **neyi yapamadığını** da şeffaf biçimde ortaya koymuştur:

1. **Windows Event Log (`.evtx`) Canlı Okuma Kısıtı:**
   - `C:\Windows\System32\winevt\Logs\System.evtx` ve `Application.evtx` dosyaları standart (yönetici olmayan) kullanıcı oturumunda işletim sistemi ACL kilidi nedeniyle `[Errno 13] Permission denied` döndürmektedir.
   - **Çözüm / İş Akışı:** Canlı triage yerine adli imajdan/kopyadan çıkarılmış `.evtx` dosyası verilmeli veya araç Yönetici (Administrator) yetkisiyle çalıştırılmalıdır.
2. **Windows Prefetch (`C:\Windows\Prefetch`) Erişim Kısıtı:**
   - Standart kullanıcı oturumunda dizin açılabilse de `.pf` dosyalarının listelenmesi Windows tarafından kısıtlanmaktadır (`tested: 0`).
   - **Not:** Çevrimdışı imajdan veya Yönetici kopyasından alınan Windows 10/11 MAM (`0x044D414D`) sıkıştırmalı Prefetch dosyalarında tam analiz için `RtlDecompressBuffer` veya harici açıcı gereksinimi uyarı olarak raporlanır.
3. **Ham RAM Dökümü ve Volatility 3 Gereksinimi:**
   - `CreateToolhelp32Snapshot` canlı çalışan Windows süreçlerini güvenilir biçimde listeler; ancak ölü kutu (dead-box) tam RAM `.raw`/`.vmem` imajlarında derin kernel `EPROCESS`/DLL/ağ nesnelerinin çözülmesi için yerleşik heuristik taramaya ek olarak **Volatility 3 CLI** köprüsü (`VolatilityBridge`) kullanılmalıdır.
