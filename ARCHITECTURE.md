# Architecture

## Genel
Katmanlı ve modüler mimari. Analiz motorları, veri modelleri ve UI birbirinden bağımsızdır. Orijinal delil salt okunur ele alınır; analizler çalışma kopyaları üzerinde yapılır.

## Katmanlar
1. UI Layer (`src/ui`) — PySide6, QSS temalar, model-view.
2. Application/Core (`src/core`) — servisler, yapılandırma, loglama, job scheduler.
3. Engine Layer (`src/*_engine`) — bağımsız analiz motorları.
4. Data Layer (`src/database`) — SQLite + SQLAlchemy + Pydantic modeller.

## Motorlar
core, case_engine, evidence_engine, integrity_engine, registry_engine, eventlog_engine, usb_engine, ntfs_engine, browser_engine, memory_engine, file_engine, timeline_engine, correlation_engine, report_engine.

## Standart Analiz Çıktısı
Artifact ID, Case ID, Evidence ID, Artifact Type, Source File, Source Location, Extracted Data, Original Timestamp, Normalized Timestamp, Parser Name, Parser Version, Confidence, Analysis Date, Warnings.

## İletişim
Motorlar standart çıktı modelleri döner; UI bunları tablolara bağlar. Uzun analizler QThread worker'larla çalıştırılır.

## Veri Akışı
Evidence intake → hash/doğrulama → analiz (salt okunur kopya) → artefakt kayıtları → timeline/correlation → rapor.

## Kısıtlar
Docker/container/WSL kullanılmaz. Tamamen çevrimdışı temel analiz. Ücretli bağımlılık yok.
