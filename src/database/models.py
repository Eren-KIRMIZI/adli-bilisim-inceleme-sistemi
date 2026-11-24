"""Forensic database models adhering to NIST digital forensic custody and artifact standards."""

import os
from datetime import datetime
from sqlalchemy import create_engine, Column, Integer, String, DateTime, Boolean, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

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

    evidences = relationship("Evidence", back_populates="case", cascade="all, delete-orphan")
    usb_records = relationship("UsbDeviceRecord", back_populates="case", cascade="all, delete-orphan")
    artifacts = relationship("ForensicArtifact", back_populates="case", cascade="all, delete-orphan")
    audit_logs = relationship("AuditLog", back_populates="case", cascade="all, delete-orphan")

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
    write_blocker_used = Column(Boolean, default=True)
    sha256_hash = Column(String(64))
    sha512_hash = Column(String(128), nullable=True)
    status = Column(String(32), default="verified")  # received, verified, analyzing, completed
    file_path = Column(String(512), nullable=True)
    notes = Column(Text, nullable=True)

    case = relationship("Case", back_populates="evidences")

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
    verification_hash = Column(String(64), nullable=True)

    case = relationship("Case", back_populates="audit_logs")

def init_db(db_path="data/forensics.db"):
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    engine = create_engine(f"sqlite:///{db_path}", echo=False)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine)
