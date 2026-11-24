# Testing

Her motor için otomatik testler. Sentetik test verileri kullanılır (gerçek kişisel veri yok).

Test senaryoları:
- Doğru veri çıkarımı
- Bozuk veri davranışı
- Eksik alan davranışı
- Zaman damgası doğrulaması
- Kaynak konumunun korunması
- Tekrarlanabilir analiz sonucu

Test veri setleri: sentetik Registry Hive, Event Log, USB kayıtları, NTFS imajları, tarayıcı SQLite DB'leri, dosya metadata, RAM örnekleri.

Çalıştırma: pytest (proje kodlaması başladığında eklenecek).
