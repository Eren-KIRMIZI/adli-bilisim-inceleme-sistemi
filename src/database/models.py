"""Forensic database models adhering to NIST digital forensic custody and artifact standards."""

import hashlib
import os
from datetime import datetime
from sqlalchemy import create_engine, event, text, Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from sqlalchemy.pool import NullPool

Base = declarative_base()

class Case(Base):
    __tablename__ = "cases"
    id = Column(Integer, primary_key=True)
    case_number = Column(String(64), unique=True, nullable=False)
    title = Column(String(255), nullable=False)
    investigator = Column(String(128))
    organization = Column(String(128))
    description = Column(Text)
    status = Column(String(32), default="open")  # open, in_progress, closed, archived
    opened_at = Column(DateTime, default=datetime.utcnow)
    closed_at = Column(DateTime, nullable=True)

    evidences = relationship("Evidence", back_populates="case", cascade="save-update, merge")
    usb_records = relationship("UsbDeviceRecord", back_populates="case", cascade="save-update, merge")
    artifacts = relationship("ForensicArtifact", back_populates="case", cascade="save-update, merge")
    audit_logs = relationship("AuditLog", back_populates="case", cascade="save-update, merge")
    custody_entries = relationship("ChainOfCustodyEntry", back_populates="case", cascade="save-update, merge")

class Evidence(Base):
    __tablename__ = "evidence"
    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    evidence_number = Column(String(64), nullable=False)
    device_type = Column(String(64))  # Disk Image, USB Flash, RAM Dump, etc.
    brand = Column(String(64))
    model = Column(String(128))
    serial = Column(String(128))
    capacity_bytes = Column(Integer, nullable=True)
    acquire_date = Column(DateTime, default=datetime.utcnow)
    custodian = Column(String(128))
    acquire_tool = Column(String(128))
    write_blocker_used = Column(Boolean, default=False)
    sha256_hash = Column(String(64))
    sha512_hash = Column(String(128), nullable=True)
    status = Column(String(32), default="received")  # received, verified, hash_mismatch, analyzing, completed
    file_path = Column(String(512), nullable=True)
    notes = Column(Text, nullable=True)

    case = relationship("Case", back_populates="evidences")
    custody_entries = relationship("ChainOfCustodyEntry", back_populates="evidence", cascade="save-update, merge")

class ChainOfCustodyEntry(Base):
    __tablename__ = "chain_of_custody"
    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    evidence_id = Column(Integer, ForeignKey("evidence.id"), nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)
    action_type = Column(String(64), nullable=False)  # Teslim Alındı, İmaj Alındı, Bütünlük Doğrulandı, Devredildi, İncelendi
    delivered_by = Column(String(128))
    received_by = Column(String(128))
    location = Column(String(128), nullable=True)
    acquire_method = Column(String(128), nullable=True)
    write_blocker_info = Column(String(128), nullable=True)
    sha256_at_event = Column(String(64), nullable=True)
    sha512_at_event = Column(String(128), nullable=True)
    verification_status = Column(String(32), default="Doğrulandı")  # Doğrulandı, Uyarı, Uyuşmazlık
    notes = Column(Text, nullable=True)

    case = relationship("Case", back_populates="custody_entries")
    evidence = relationship("Evidence", back_populates="custody_entries")

class UsbDeviceRecord(Base):
    __tablename__ = "usb_device_records"
    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    evidence_id = Column(Integer, ForeignKey("evidence.id"), nullable=True)
    device_name = Column(String(255))
    vendor = Column(String(128))
    product = Column(String(128))
    revision = Column(String(64), nullable=True)
    vid = Column(String(16))
    pid = Column(String(16))
    serial_number = Column(String(128))
    drive_letter = Column(String(8), nullable=True)
    volume_guid = Column(String(128), nullable=True)
    first_connected = Column(DateTime, nullable=True)
    last_connected = Column(DateTime, nullable=True)
    last_removed = Column(DateTime, nullable=True)
    user_account = Column(String(128), nullable=True)
    user_sid = Column(String(128), nullable=True)
    registry_source_key = Column(String(512))
    device_class = Column(String(64), default="USBSTOR")  # USBSTOR, MTP, HID, HUB
    status = Column(String(32), default="Normal")  # Normal, İnceleniyor, Şüpheli, Doğrulandı
    confidence = Column(Integer, default=100)  # % confidence
    is_suspicious = Column(Boolean, default=False)
    notes = Column(Text, nullable=True)
    raw_details = Column(Text, nullable=True)  # JSON formatted strings

    case = relationship("Case", back_populates="usb_records")

class ForensicArtifact(Base):
    __tablename__ = "forensic_artifacts"
    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=False)
    evidence_id = Column(Integer, ForeignKey("evidence.id"), nullable=True)
    artifact_type = Column(String(64))  # USB, Registry, EventLog, Browser, File, etc.
    source_path = Column(String(512))
    source_location = Column(String(512))
    extracted_data = Column(Text)  # JSON
    original_timestamp = Column(String(64), nullable=True)
    normalized_timestamp = Column(DateTime, nullable=True)
    parser_name = Column(String(128))
    parser_version = Column(String(32))
    confidence = Column(Integer, default=100)
    analysis_date = Column(DateTime, default=datetime.utcnow)
    warnings = Column(Text, nullable=True)

    case = relationship("Case", back_populates="artifacts")

class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    case_id = Column(Integer, ForeignKey("cases.id"), nullable=True)
    timestamp = Column(DateTime, default=datetime.utcnow)
    investigator = Column(String(128))
    action = Column(String(128))
    details = Column(Text)
    prev_hash = Column(String(64), nullable=True)
    verification_hash = Column(String(64), nullable=True)

    case = relationship("Case", back_populates="audit_logs")


def _compute_audit_entry_hash(
    prev_hash: str,
    case_id,
    ts_iso: str,
    investigator: str,
    action: str,
    details: str,
) -> str:
    payload = f"{prev_hash}|{case_id or ''}|{ts_iso}|{investigator}|{action}|{details}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def append_audit_log(session, case_id, investigator: str, action: str, details: str) -> AuditLog:
    """Append an immutable hash-chained audit entry linking previous entry's 64-char SHA-256."""
    last = session.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_h = (last.verification_hash or "GENESIS") if last else "GENESIS"
    now = datetime.utcnow().replace(microsecond=0)
    inv = (investigator or "Adli Bilişim Uzmanı").strip()
    act = action.strip()
    det = (details or "").strip()
    cur_h = _compute_audit_entry_hash(prev_h, case_id, now.isoformat(), inv, act, det)
    entry = AuditLog(
        case_id=case_id,
        timestamp=now,
        investigator=inv,
        action=act,
        details=det,
        prev_hash=prev_h,
        verification_hash=cur_h,
    )
    session.add(entry)
    return entry


def verify_audit_chain(session) -> dict:
    """Verify integrity of hash-chained AuditLog entries (entries with prev_hash)."""
    rows = session.query(AuditLog).order_by(AuditLog.id.asc()).all()
    checked = 0
    broken = []
    for i, row in enumerate(rows):
        if row.prev_hash is None:
            continue
        checked += 1
        expected_prev = (rows[i - 1].verification_hash or "GENESIS") if i > 0 else "GENESIS"
        if i > 0 and rows[i - 1].prev_hash is not None and row.prev_hash != expected_prev:
            broken.append({"id": row.id, "reason": "Önceki kayıt hash bağı kopuk"})
            continue
        ts_iso = row.timestamp.replace(microsecond=0).isoformat() if row.timestamp else ""
        recalc = _compute_audit_entry_hash(
            row.prev_hash, row.case_id, ts_iso, row.investigator or "", row.action or "", row.details or ""
        )
        if row.verification_hash != recalc:
            broken.append({"id": row.id, "reason": "Denetim kaydı içeriği hash uyuşmazlığı (olası müdahale)"})
    return {"checked": checked, "intact": len(broken) == 0, "broken": broken}


def init_db(db_path="data/forensics.db"):
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    engine = create_engine(
        f"sqlite:///{db_path}",
        echo=False,
        poolclass=NullPool,
        connect_args={"timeout": 10},
    )

    @event.listens_for(engine, "connect")
    def _set_sqlite_pragmas(dbapi_connection, _connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=FULL;")
        cursor.execute("PRAGMA foreign_keys=ON;")
        cursor.execute("PRAGMA busy_timeout=5000;")
        cursor.close()

    Base.metadata.create_all(engine)
    # Lightweight schema migration for existing SQLite files missing new audit_logs.prev_hash column
    with engine.connect() as conn:
        cols = {row[1] for row in conn.execute(text("PRAGMA table_info(audit_logs)")).fetchall()}
        if "prev_hash" not in cols:
            conn.execute(text("ALTER TABLE audit_logs ADD COLUMN prev_hash VARCHAR(64)"))
            conn.commit()
    return sessionmaker(bind=engine, expire_on_commit=False)
