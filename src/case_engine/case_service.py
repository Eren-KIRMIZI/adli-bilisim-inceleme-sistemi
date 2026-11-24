"""Case Management service engine for digital forensic investigations."""

from datetime import datetime
from typing import List, Dict, Any, Optional
import hashlib

from src.database.models import init_db, Case, Evidence, UsbDeviceRecord, ForensicArtifact, AuditLog
from src.database.seed import seed_database_if_empty


class CaseService:
    """Manages forensic cases, lifecycle status transitions, and case-level audit trails."""

    STATUS_LABELS = {
        "open": "Açık",
        "in_progress": "İncelemede",
        "closed": "Kapandı",
        "archived": "Arşivlendi",
    }

    def __init__(self, db_path: str = "data/forensics.db"):
        self.db_path = db_path
        self.Session = init_db(db_path)
        seed_database_if_empty(db_path)

    def list_cases(self, status_filter: Optional[str] = None) -> List[Case]:
        """Return all cases ordered newest first, optionally filtered by status."""
        with self.Session() as s:
            q = s.query(Case)
            if status_filter and status_filter != "all":
                q = q.filter(Case.status == status_filter)
            return q.order_by(Case.id.desc()).all()

    def get_case(self, case_id: int) -> Optional[Case]:
        """Return a single case by ID."""
        with self.Session() as s:
            return s.query(Case).filter(Case.id == case_id).first()

    def create_case(
        self,
        case_number: str,
        title: str,
        investigator: str = "",
        description: str = "",
        organization: str = "",
        status: str = "open",
    ) -> Case:
        """Create a new forensic case and record an audit log entry."""
        case_number = case_number.strip()
        title = title.strip()
        if not case_number or not title:
            raise ValueError("Vaka numarası ve başlığı boş olamaz.")

        with self.Session() as s:
            existing = s.query(Case).filter(Case.case_number == case_number).first()
            if existing:
                raise ValueError(f"'{case_number}' numaralı vaka zaten mevcut.")

            c = Case(
                case_number=case_number,
                title=title,
                investigator=investigator.strip(),
                organization=organization.strip(),
                description=description.strip(),
                status=status,
                opened_at=datetime.utcnow(),
            )
            s.add(c)
            s.flush()

            vhash = hashlib.sha256(f"{c.case_number}:{c.title}:{datetime.utcnow().isoformat()}".encode()).hexdigest()[:32]
            s.add(AuditLog(
                case_id=c.id,
                investigator=investigator.strip() or "Adli Bilişim Uzmanı",
                action="Vaka Oluşturuldu",
                details=f"{c.case_number} ({c.title}) soruşturma kaydı açıldı.",
                verification_hash=vhash,
            ))
            s.commit()
            s.refresh(c)
            return c

    def update_case(
        self,
        case_id: int,
        title: Optional[str] = None,
        investigator: Optional[str] = None,
        organization: Optional[str] = None,
        description: Optional[str] = None,
        status: Optional[str] = None,
    ) -> Optional[Case]:
        """Update case metadata or status and log the change."""
        with self.Session() as s:
            c = s.query(Case).filter(Case.id == case_id).first()
            if not c:
                return None

            changes = []
            if title is not None and title.strip() != c.title:
                c.title = title.strip()
                changes.append("başlık")
            if investigator is not None and investigator.strip() != (c.investigator or ""):
                c.investigator = investigator.strip()
                changes.append("sorumlu")
            if organization is not None and organization.strip() != (c.organization or ""):
                c.organization = organization.strip()
                changes.append("birim")
            if description is not None and description.strip() != (c.description or ""):
                c.description = description.strip()
                changes.append("açıklama")
            if status is not None and status != c.status:
                c.status = status
                c.closed_at = datetime.utcnow() if status in ("closed", "archived") else None
                changes.append(f"durum->{status}")

            if changes:
                s.add(AuditLog(
                    case_id=c.id,
                    investigator=c.investigator or "Adli Bilişim Uzmanı",
                    action="Vaka Güncellendi",
                    details=f"{c.case_number} güncellendi ({', '.join(changes)}).",
                ))
            s.commit()
            s.refresh(c)
            return c

    def get_case_summary(self, case_id: int) -> Dict[str, Any]:
        """Return counts and related records for a specific case."""
        with self.Session() as s:
            c = s.query(Case).filter(Case.id == case_id).first()
            if not c:
                return {}
            evidences = s.query(Evidence).filter(Evidence.case_id == case_id).order_by(Evidence.id.desc()).all()
            usb_count = s.query(UsbDeviceRecord).filter(UsbDeviceRecord.case_id == case_id).count()
            art_count = s.query(ForensicArtifact).filter(ForensicArtifact.case_id == case_id).count()
            logs = s.query(AuditLog).filter(AuditLog.case_id == case_id).order_by(AuditLog.timestamp.desc()).limit(30).all()
            return {
                "case": c,
                "evidence_count": len(evidences),
                "evidences": evidences,
                "usb_count": usb_count,
                "artifact_count": art_count,
                "audit_logs": logs,
            }
