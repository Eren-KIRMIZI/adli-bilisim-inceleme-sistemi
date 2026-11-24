# Adli Bilişim İnceleme Sistemi

Özgün bir masaüstü dijital adli bilişim inceleme uygulaması (Digital Forensics Suite). Windows bilgisayarlar, disk/RAM imajları ve dijital artefaktların vaka bazlı incelenmesi, ilişkilendirilmesi ve raporlanması için tasarlanmıştır.

## Durum
Aşama 1 — Proje iskeleti, mimari ve dokümantasyon. Kodlama henüz başlamadı (onay bekleniyor).

## Mimari
Modüler motor mimarisi. Her analiz motoru bağımsız çalışır, standart analiz çıktı modeli üretir. UI (PySide6) ve veri katmanı (SQLite/SQLAlchemy) analiz motorlarından bağımsızdır.

## Teknoloji
Python 3.12+, PySide6, SQLite, SQLAlchemy, Pydantic, ReportLab, Jinja2, Matplotlib.

## Dokümanlar
- `ARCHITECTURE.md`
- `MODULES.md`
- `DATABASE_SCHEMA.md`
- `DEVELOPMENT_ROADMAP.md`
- `LICENSES.md`
- `SECURITY.md`
- `TESTING.md`

## Lisans
Proje lisansı belirlenecektir (önerilen: MIT/Apache-2.0). Bağımlılık lisansları `LICENSES.md` içinde takip edilir.
