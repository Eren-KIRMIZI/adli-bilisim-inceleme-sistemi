"""Evidence Manager service engine with Chain of Custody & hash tracking."""

from datetime import datetime
from typing import List, Optional, Dict, Any
import hashlib

from src.database.models import init_db, Evidence, Case, ChainOfCustodyEntry, AuditLog
from src.database.seed import seed_database_if_empty


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
        write_blocker_used: bool = True,
        sha256_hash: str = "",
        sha512_hash: str = "",
        file_path: str = "",
        notes: str = "",
        delivered_by: str = "Olay Yeri / Teslim Eden",
        status: str = "received",
    ) -> Evidence:
        """Register a new digital evidence item and record initial custody & audit entries."""
        evd_num = (evidence_number or "").strip() or self.generate_evidence_number(case_id)
        if sha256_hash and not status:
            status = "verified"
        elif sha256_hash and status == "received":
            status = "verified"

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
                write_blocker_used=write_blocker_used,
                sha256_hash=sha256_hash.strip().lower(),
                sha512_hash=sha512_hash.strip().lower() if sha512_hash else None,
                status=status,
                file_path=file_path.strip() or None,
                notes=notes.strip() or None,
            )
            s.add(evd)
            s.flush()

            wb_desc = acquire_tool.strip() or ("Donanımsal Yazma Engelleyici Kullanıldı" if write_blocker_used else "Yazma Engelleyici Belirtilmedi")
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
                verification_status="Doğrulandı" if evd.sha256_hash else "Uyarı",
                notes=notes.strip() or "İlk delil kabul kaydı oluşturuldu.",
            ))

            vhash = hashlib.sha256(f"{evd.evidence_number}:{evd.serial}:{evd.sha256_hash}".encode()).hexdigest()[:32]
            s.add(AuditLog(
                case_id=case_id,
                investigator=custodian.strip() or "Adli Bilişim Uzmanı",
                action="Delil Kabul Edildi",
                details=f"{evd.evidence_number} ({evd.brand} {evd.model} - {evd.device_type}) envantere eklendi.",
                verification_hash=evd.sha256_hash[:32] if evd.sha256_hash else vhash,
            ))

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
            s.add(AuditLog(
                case_id=evd.case_id,
                investigator=evd.custodian or "Adli Bilişim Uzmanı",
                action="Delil Durumu Güncellendi",
                details=f"{evd.evidence_number} durumu '{status}' olarak güncellendi.",
            ))
            s.commit()
            s.refresh(evd)
            return evd
