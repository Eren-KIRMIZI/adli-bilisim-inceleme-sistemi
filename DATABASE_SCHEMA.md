# Database Schema

SQLite + SQLAlchemy. Temel tablolar:

- cases (id, case_number, title, investigator, description, status, opened_at, closed_at)
- evidence (id, case_id, device_type, brand, model, serial, acquired_at, custodian, status)
- evidence_files (id, evidence_id, path, sha256, sha512, size, is_working_copy)
- custody_entries (id, evidence_id, action, user, timestamp, notes)
- audit_log (id, case_id, user, action, target, timestamp, details_json)
- artifacts (id, case_id, evidence_id, artifact_type, source_file, source_location, extracted_data_json, original_ts, normalized_ts, parser_name, parser_version, confidence, analysis_date, warnings_json)
- timeline_events (id, case_id, artifact_id, event_type, timestamp_utc, original_ts, timezone, source, details_json)
- relations (id, case_id, from_type, from_id, to_type, to_id, relation_type, evidence_source, confidence)
- reports (id, case_id, format, path, generated_at, app_version)

Tüm tablolarda created_at/updated_at. İndeksler case_id, evidence_id, timestamp üzerinde.
