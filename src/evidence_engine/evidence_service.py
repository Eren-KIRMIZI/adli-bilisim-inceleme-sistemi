"""Evidence Manager service engine with Chain of Custody & hash tracking."""

from datetime import datetime
from typing import List, Optional, Dict, Any
import hashlib
import os
import re

from src.database.models import init_db, Evidence, Case, ChainOfCustodyEntry, append_audit_log
from src.database.seed import seed_database_if_empty
from src.integrity_engine.integrity_service import IntegrityService


class EvidenceService:
    """Manages digital evidence intake, inventory, and custody initialization."""

    def __init__(self, db_path: str = "data/forensics.db"):
        self.db_path = db_path
        self.Session = init_db(db_path)
        seed_database_if_empty(db_path)

    def list_evidence(self, case_id: Optional[int] = None) -> List[Evidence]:
        """List all evidence items, optionally filtered by case_id."""
        with self.Session() as s:
            q = s.query(Evidence)
            if case_id:
                q = q.filter(Evidence.case_id == case_id)
            return q.order_by(Evidence.id.desc()).all()

    def list_evidence_with_case(self, case_id: Optional[int] = None) -> List[Dict[str, Any]]:
        """List evidence records joined with their parent case number."""
        with self.Session() as s:
            q = s.query(Evidence, Case.case_number).join(Case, Evidence.case_id == Case.id)
            if case_id:
                q = q.filter(Evidence.case_id == case_id)
            rows = q.order_by(Evidence.id.desc()).all()
            result = []
            for evd, case_num in rows:
                cust_count = s.query(ChainOfCustodyEntry).filter(ChainOfCustodyEntry.evidence_id == evd.id).count()
                result.append({
                    "evidence": evd,
                    "case_number": case_num,
                    "custody_count": cust_count,
                })
            return result

    def get_evidence(self, evidence_id: int) -> Optional[Evidence]:
        with self.Session() as s:
            return s.query(Evidence).filter(Evidence.id == evidence_id).first()

    def generate_evidence_number(self, case_id: int) -> str:
        """Generate sequential evidence number like EVD-2026-004."""
        year = datetime.utcnow().year
        with self.Session() as s:
            count = s.query(Evidence).filter(Evidence.case_id == case_id).count()
            return f"EVD-{year}-{count + 1:03d}"

    def add_evidence(
        self,
        case_id: int,
        device_type: str,
        brand: str = "",
        model: str = "",
        serial: str = "",
        custodian: str = "",
        evidence_number: Optional[str] = None,
        capacity_bytes: Optional[int] = None,
        acquire_tool: str = "",
        write_blocker_used: bool = False,
        sha256_hash: str = "",
        sha512_hash: str = "",
        file_path: str = "",
        notes: str = "",
        delivered_by: str = "Olay Yeri / Teslim Eden",
        status: str = "received",
    ) -> Evidence:
        """Register a new digital evidence item and verify hashes strictly against disk when available."""
        evd_num = (evidence_number or "").strip() or self.generate_evidence_number(case_id)
        clean_sha256 = sha256_hash.strip().lower()
        clean_sha512 = sha512_hash.strip().lower() if sha512_hash else None
        clean_path = file_path.strip() or None

        if clean_sha256 and not re.fullmatch(r"[0-9a-f]{64}", clean_sha256):
            raise ValueError("Geçersiz SHA-256 formatı: 64 karakterlik hexadecimal özet gereklidir.")
        if clean_sha512 and not re.fullmatch(r"[0-9a-f]{128}", clean_sha512):
            raise ValueError("Geçersiz SHA-512 formatı: 128 karakterlik hexadecimal özet gereklidir.")

        # Strict verification rule: never trust unverified/arbitrary strings as 'verified'.
        custody_status = "Doğrulanmadı"
        if clean_path and os.path.isfile(clean_path):
            computed = IntegrityService.compute_dual_hashes(clean_path)
            if not clean_sha256:
                clean_sha256 = computed["sha256"]
                clean_sha512 = clean_sha512 or computed["sha512"]
                status = "verified"
                custody_status = "Doğrulandı"
            elif computed["sha256"] == clean_sha256 and (not clean_sha512 or computed["sha512"] == clean_sha512):
                status = "verified"
                custody_status = "Doğrulandı"
            else:
                status = "hash_mismatch"
                custody_status = "Uyuşmazlık"
        else:
            # No file on disk to independently verify hash against
            status = status if status != "verified" else "received"
            custody_status = "Doğrulanmadı (Dosya Yok)" if clean_sha256 else "Uyarı"

        with self.Session() as s:
            evd = Evidence(
                case_id=case_id,
                evidence_number=evd_num,
                device_type=device_type.strip(),
                brand=brand.strip(),
                model=model.strip(),
                serial=serial.strip(),
                capacity_bytes=capacity_bytes,
                acquire_date=datetime.utcnow(),
                custodian=custodian.strip(),
                acquire_tool=acquire_tool.strip(),
                write_blocker_used=bool(write_blocker_used),
                sha256_hash=clean_sha256,
                sha512_hash=clean_sha512,
                status=status,
                file_path=clean_path,
                notes=notes.strip() or None,
            )
            s.add(evd)
            s.flush()

            wb_desc = acquire_tool.strip() or (
                "Donanımsal Yazma Engelleyici İşaretlendi" if write_blocker_used else "Yazma Engelleyici Belirtilmedi"
            )
            s.add(ChainOfCustodyEntry(
                case_id=case_id,
                evidence_id=evd.id,
                timestamp=datetime.utcnow(),
                action_type="Delil Kabul Edildi",
                delivered_by=delivered_by.strip() or "Belirtilmedi",
                received_by=custodian.strip() or "Adli Bilişim Uzmanı",
                location="Delil Kabul Masası",
                acquire_method=device_type.strip(),
                write_blocker_info=wb_desc,
                sha256_at_event=evd.sha256_hash or None,
                sha512_at_event=evd.sha512_hash or None,
                verification_status=custody_status,
                notes=notes.strip() or "İlk delil kabul kaydı oluşturuldu.",
            ))

            append_audit_log(
                s,
                case_id,
                custodian.strip() or "Adli Bilişim Uzmanı",
                "Delil Kabul Edildi",
                f"{evd.evidence_number} ({evd.brand} {evd.model} - {evd.device_type}) | Durum: {status} | WB: {bool(write_blocker_used)}",
            )

            s.commit()
            s.refresh(evd)
            return evd

    def update_evidence_status(self, evidence_id: int, status: str, notes: str = "") -> Optional[Evidence]:
        with self.Session() as s:
            evd = s.query(Evidence).filter(Evidence.id == evidence_id).first()
            if not evd:
                return None
            evd.status = status
            if notes:
                evd.notes = ((evd.notes + "\n") if evd.notes else "") + notes
            append_audit_log(
                s,
                evd.case_id,
                evd.custodian or "Adli Bilişim Uzmanı",
                "Delil Durumu Güncellendi",
                f"{evd.evidence_number} durumu '{status}' olarak güncellendi.",
            )
            s.commit()
            s.refresh(evd)
            return evd
