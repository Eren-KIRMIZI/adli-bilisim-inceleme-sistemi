# Licenses

Bağımlılıklar ve lisansları proje ilkeleri gereği doğrulanmıştır. Yalnızca ticari kullanıma açık ve uygun açık kaynak lisanslı (MIT, BSD-2-Clause, BSD-3-Clause, Apache-2.0, PSF, LGPL-3.0) paketler kullanılır.

| Paket | Lisans | Durum | Kullanım Amacı |
|---|---|---|---|
| Python | PSF License | onaylı | Çekirdek çalışma zamanı ve standart kütüphane binary ayrıştırıcıları |
| PySide6 | LGPL-3.0 (Qt) | onaylı | Masaüstü Qt Widgets arayüz katmanı |
| SQLAlchemy | MIT | onaylı | SQLite veritabanı ORM katmanı |
| Pydantic | MIT | onaylı | Standart analiz çıktısı veri şeması (`ForensicArtifactModel`) |
| ReportLab | BSD | onaylı | Çevrimdışı PDF adli inceleme raporu oluşturma |
| Jinja2 | BSD-3-Clause | onaylı | Denetlenebilir HTML adli rapor şablonlama |
| Matplotlib | PSF / BSD | onaylı | Görselleştirme desteği |
| NetworkX | BSD-3-Clause | onaylı | Evidence Relations grafik düzeni ve düğüm/kenar topolojisi |
| pytest | MIT | onaylı | Otomatik birim ve arayüz test doğrulaması |

> **Not:** Autopsy, FTK, EnCase gibi ticari yazılımlara bağımlılık yoktur. The Sleuth Kit, Volatility ve Plaso ana analiz motoru olarak kullanılmamaktadır; tüm disk, Registry Hive, EVTX, USB, tarayıcı, dosya ve bellek analiz motorları Python standart kütüphaneleriyle özgün olarak geliştirilmiştir.
