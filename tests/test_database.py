"""Unit tests for SQLite forensic models and seed data."""

import os
import pytest
from src.database.models import init_db, Case, Evidence, UsbDeviceRecord, AuditLog
from src.database.seed import seed_database_if_empty

@pytest.fixture
def test_db(tmp_path):
    db_file = str(tmp_path / "test_forensics.db")
    Session = init_db(db_file)
    return db_file, Session

def test_database_creation_and_seeding(test_db):
    db_file, Session = test_db
    seed_database_if_empty(db_file)

    with Session() as s:
        case = s.query(Case).first()
        assert case is not None
        assert case.case_number == "VAK-2026-084"
        assert len(case.evidences) == 3
        assert len(case.usb_records) == 4
        assert len(case.audit_logs) >= 4

        # Check evidence integrity properties
        evd = s.query(Evidence).filter(Evidence.evidence_number == "EVD-2026-001").first()
        assert evd.write_blocker_used is True
        assert len(evd.sha256_hash) == 64

        # Check suspicious USB record
        susp = s.query(UsbDeviceRecord).filter(UsbDeviceRecord.is_suspicious == True).first()
        assert susp is not None
        assert "BadUSB" in susp.device_name
