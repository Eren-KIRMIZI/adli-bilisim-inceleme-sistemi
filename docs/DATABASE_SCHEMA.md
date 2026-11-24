# Database Schema

Veritabanı motoru: **SQLite (WAL modu, `PRAGMA synchronous=FULL`, `foreign_keys=ON`)** + **SQLAlchemy ORM** (`src/database/models.py`).

## Aktif Tablolar

- **`cases`**: `id`, `case_number` (unique), `title`, `investigator`, `organization`, `description`, `status` (`open`, `in_progress`, `closed`, `archived`), `opened_at`, `closed_at`
- **`evidence`**: `id`, `case_id` (FK), `evidence_number`, `device_type`, `brand`, `model`, `serial`, `capacity_bytes`, `acquire_date`, `custodian`, `acquire_tool`, `write_blocker_used`, `sha256_hash`, `sha512_hash`, `status`, `file_path`, `notes`
- **`chain_of_custody`**: `id`, `case_id` (FK), `evidence_id` (FK), `timestamp`, `action_type`, `delivered_by`, `received_by`, `location`, `acquire_method`, `write_blocker_info`, `sha256_at_event`, `sha512_at_event`, `verification_status`, `notes`
- **`usb_device_records`**: `id`, `case_id` (FK), `evidence_id` (FK), `device_name`, `vendor`, `product`, `revision`, `vid`, `pid`, `serial_number`, `drive_letter`, `volume_guid`, `first_connected`, `last_connected`, `last_removed`, `user_account`, `user_sid`, `registry_source_key`, `device_class`, `status`, `confidence`, `is_suspicious`, `notes`, `raw_details`
- **`forensic_artifacts`**: `id`, `case_id` (FK), `evidence_id` (FK), `artifact_type`, `source_path`, `source_location`, `extracted_data` (JSON), `original_timestamp`, `normalized_timestamp`, `parser_name`, `parser_version`, `confidence`, `analysis_date`, `warnings`
- **`audit_logs`**: `id`, `case_id` (FK), `timestamp`, `investigator`, `action`, `details`, `verification_hash`

## Yedekleme ve Bütünlük
- İlk açılışta `src/database/seed.py` örnek vaka (`VAK-2026-084`), 3 delil, 4 muhafaza zinciri kaydı, 4 USB cihazı ve denetim günlüklerini oluşturur.
- `RecoveryManager.create_verified_db_backup()` ile `data/backups/forensics_backup_*.db` ve `.sha256` doğrulama dosyaları üretilir.
