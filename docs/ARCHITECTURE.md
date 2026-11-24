# Architecture

## Genel
Katmanlı ve modüler mimari. Analiz motorları, veri modelleri ve kullanıcı arayüzü birbirinden bağımsızdır. Orijinal delil salt-okunur ele alınır; analizler çalışma kopyaları üzerinde yapılır ve kritik durumlar için elektrik kesintisi/çökme kurtarma mekanizması aktiftir.

## Katmanlar
1. **UI Layer (`src/ui`)** — PySide6, Fusion tabanlı Açık/Koyu QSS tasarım tokenları (`tokens.py`, `light.qss`, `dark.qss`), `QThread` destekli model-view bileşenler ve 14 entegre sayfa.
2. **Core Infrastructure (`src/core`)** — Standart Pydantic çıktı şeması (`ForensicArtifactModel`) ve atomik oturum/elektrik kesintisi kurtarma motoru (`RecoveryManager`).
3. **Engine Layer (`src/*_engine`)** — Her biri bağımsız çalışabilen özgün ikili (binary) ve veritabanı analiz motorları:
   - `case_engine`, `evidence_engine`, `integrity_engine`
   - `ntfs_engine`, `registry_engine`, `eventlog_engine`, `usb_engine`
   - `browser_engine`, `memory_engine`, `file_engine`
   - `timeline_engine`, `correlation_engine`, `report_engine`
4. **Data Layer (`src/database`)** — SQLite (`PRAGMA journal_mode=WAL`, `PRAGMA synchronous=FULL`, `foreign_keys=ON`) + SQLAlchemy ORM + örnek vaka üretici (`seed.py`).

## Standart Analiz Çıktısı (`ForensicArtifactModel`)
`artifact_id`, `case_id`, `evidence_id`, `artifact_type`, `source_file`, `source_location`, `extracted_data`, `original_timestamp`, `normalized_timestamp`, `parser_name`, `parser_version`, `confidence`, `analysis_date`, `warnings`.

## Dayanıklılık ve Veri Akışı
- **Veri Akışı**: Delil kabul → SHA-256/512 doğrulama & muhafaza zinciri → salt-okunur analiz → zaman çizelgesi & ilişkilendirme → HTML/PDF rapor.
- **Kesinti Koruması**: SQLite WAL modu + 30 saniyelik atomik `fsync` kontrol noktaları (`session_recovery.json`) + kapanışta SHA-256 doğrulamalı `sqlite3.Connection.backup()` yedeklemesi.

## Kısıtlar
Docker, container veya WSL kullanılmaz. Tüm temel analizler çevrimdışı ve doğrudan Windows üzerinde çalışır. Ücretli/ticari bağımlılık yoktur.
