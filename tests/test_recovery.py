"""Tests for SQLite WAL durability, crash/power-loss recovery, and verified backups."""

import os
import sqlite3
from src.core.recovery import RecoveryManager
from src.database.models import init_db
from src.database.seed import seed_database_if_empty


def test_sqlite_wal_mode_enabled(tmp_path):
    db_file = str(tmp_path / "wal_test.db")
    Session = init_db(db_file)
    with Session():
        pass

    con = sqlite3.connect(db_file)
    mode = con.execute("PRAGMA journal_mode;").fetchone()[0]
    con.close()
    assert mode.lower() == "wal"


def test_power_loss_unclean_shutdown_recovery(tmp_path):
    data_dir = str(tmp_path / "data")
    rm1 = RecoveryManager(data_dir=data_dir)
    rm1.begin_session()
    assert rm1.unclean_shutdown_detected is False

    rm1.save_checkpoint(
        active_case_id=42,
        active_evidence_id=7,
        page_index=6,
        theme="dark",
        report_draft={"expert_notes": "Elektrik kesintisi öncesi taslak"},
    )
    # Simulate sudden power loss (do NOT call end_session_cleanly!)

    rm2 = RecoveryManager(data_dir=data_dir)
    recovered = rm2.begin_session()
    assert rm2.unclean_shutdown_detected is True
    assert recovered["active_case_id"] == 42
    assert recovered["active_evidence_id"] == 7
    assert recovered["page_index"] == 6
    assert recovered["theme"] == "dark"
    assert recovered["report_draft"]["expert_notes"] == "Elektrik kesintisi öncesi taslak"

    # Now exit cleanly and confirm next startup has no unclean flag
    rm2.end_session_cleanly()
    rm3 = RecoveryManager(data_dir=data_dir)
    rm3.begin_session()
    assert rm3.unclean_shutdown_detected is False


def test_verified_sqlite_backup_with_sha256(tmp_path):
    data_dir = str(tmp_path / "data")
    db_file = os.path.join(data_dir, "forensics.db")
    seed_database_if_empty(db_file)

    rm = RecoveryManager(data_dir=data_dir)
    bkp = rm.create_verified_db_backup(db_file)
    assert bkp is not None and os.path.isfile(bkp)
    assert os.path.isfile(bkp + ".sha256")
