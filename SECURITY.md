# Security

- Orijinal deliller salt okunur ele alınır; doğrudan analiz yapılmaz.
- Çalışma kopyalarının hash değerleri takip edilir.
- Tüm analiz işlemleri audit_log'a kaydedilir.
- Parser sürümleri artefakt kayıtlarında saklanır.
- Eksik/bozuk veri açıkça işaretlenir.
- Hassas veriler (parola/token) varsayılan olarak çıkarılmaz/raporlanmaz.
- Uygulama yazma engelleyici donanımın yerini almadığını beyan eder.
- Girdi doğrulama ve path traversal koruması uygulanacak.
- SQL injection'a karşı ORM parametreli sorgular kullanılacak.
