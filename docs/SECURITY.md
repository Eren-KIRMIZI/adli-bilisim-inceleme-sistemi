# Security & Forensic Reliability

- **Salt-Okunur İşleme**: Orijinal deliller ve tarayıcı SQLite veritabanları (`?mode=ro`) salt-okunur açılır; doğrudan değişiklik yapılmaz.
- **Bütünlük & Muhafaza Zinciri**: Her delil için SHA-256 ve SHA-512 takip edilir; erişim amacı (UNODC Modül 6), donanım ve yazma engelleyici bilgileri kaydedilir.
- **Yazma Engelleyici Beyanı**: Uygulama donanımsal yazma engelleyicinin (hardware write-blocker) yerini aldığı iddiasında bulunmaz; bu kısıtlama raporlarda açıkça belirtilir.
- **Denetim Kayıtları**: Kritik vaka, delil, muhafaza ve USB analiz işlemleri `audit_logs` tablosuna zaman damgasıyla eklenir.
- **Veri Doğruluğu ve Gizlilik**:
  - Eksik veya bozuk alanlar tahmin edilmez; açıkça işaretlenir veya hata yükseltilir.
  - Desteklenmeyen RAM/imaj formatlarında uydurma sonuç üretilmez.
  - Parola ve oturum çerez değerleri varsayılan olarak çıkarılmaz ve maskelenir.
- **Elektrik Kesintisi & Çökme Koruması**:
  - SQLite `WAL` modu ve `PRAGMA synchronous=FULL` ile işlem bütünlüğü korunur.
  - `RecoveryManager`, atomik `fsync` + `os.replace` oturum kontrol noktaları ve kapanışta SHA-256 doğrulamalı yedekler üretir.
- **SQL Injection Koruması**: Tüm veritabanı sorguları SQLAlchemy ORM parametreli sorgularıyla yürütülür.
