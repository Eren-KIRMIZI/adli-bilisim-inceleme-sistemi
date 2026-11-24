"""Integrity & Chain of Custody engine with SHA-256 / SHA-512 verification."""

import hashlib
import os
from datetime import datetime
from typing import Callable, Dict, Any, List, Optional, Tuple

from src.database.models import init_db, ChainOfCustodyEntry, Evidence, AuditLog
from src.database.seed import seed_database_if_empty


class IntegrityService:
    """Provides read-only cryptographic hashing and Chain of Custody management."""

    def __init__(self, db_path: str = "data/forensics.db"):
        self.db_path = db_path
        self.Session = init_db(db_path)
        seed_database_if_empty(db_path)

    @staticmethod
    def hash_file(path: str, algo: str = "sha256") -> str:
        """Compute single cryptographic hash for a file in read-only binary mode."""
        h = hashlib.new(algo)
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    @staticmethod
    def compute_dual_hashes(
        path: str,
        progress_callback: Optional[Callable[[int], None]] = None,
        cancel_check: Optional[Callable[[], bool]] = None,
    ) -> Dict[str, Any]:
        """Compute SHA-256 and SHA-512 in a single read-only pass with optional progress reporting."""
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Dosya bulunamadı: {path}")

        total_size = os.path.getsize(path)
        h256 = hashlib.sha256()
        h512 = hashlib.sha512()
        read_bytes = 0
        chunk_size = 262144  # 256 KB

        with open(path, "rb") as f:
            while True:
                if cancel_check and cancel_check():
                    raise InterruptedError("Hash hesaplama işlemi kullanıcı tarafından iptal edildi.")
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h256.update(chunk)
                h512.update(chunk)
                read_bytes += len(chunk)
                if progress_callback and total_size > 0:
                    pct = min(100, int((read_bytes * 100) / total_size))
                    progress_callback(pct)

        if progress_callback:
            progress_callback(100)

        return {
            "file_path": path,
            "file_name": os.path.basename(path),
            "file_size": total_size,
            "sha256": h256.hexdigest(),
            "sha512": h512.hexdigest(),
            "computed_at": datetime.utcnow(),
        }

    @staticmethod
    def verify(path: str, expected: str, algo: str = "sha256") -> bool:
        """Verify file against expected hex digest."""
        return IntegrityService.hash_file(path, algo).lower() == expected.strip().lower()

    @staticmethod
    def verify_detailed(path: str, expected_hash: str) -> Dict[str, Any]:
        """Verify file against expected SHA-256 or SHA-512 hash and return detailed forensic result."""
        expected = expected_hash.strip().lower()
        res = IntegrityService.compute_dual_hashes(path)
        algo_used = "SHA-512" if len(expected) == 128 else "SHA-256" if len(expected) == 64 else "Bilinmeyen Uzunluk"
        matched = False
        if len(expected) == 64:
            matched = (res["sha256"].lower() == expected)
        elif len(expected) == 128:
            matched = (res["sha512"].lower() == expected)

        res["expected_hash"] = expected
        res["algo_detected"] = algo_used
        res["matched"] = matched
        return res

    def list_custody_records(
        self,
        case_id: Optional[int] = None,
        evidence_id: Optional[int] = None,
    ) -> List[Dict[str, Any]]:
        """List Chain of Custody entries joined with Evidence number."""
        with self.Session() as s:
            q = s.query(ChainOfCustodyEntry, Evidence.evidence_number).join(
                Evidence, ChainOfCustodyEntry.evidence_id == Evidence.id
            )
            if case_id:
                q = q.filter(ChainOfCustodyEntry.case_id == case_id)
            if evidence_id:
                q = q.filter(ChainOfCustodyEntry.evidence_id == evidence_id)
            rows = q.order_by(ChainOfCustodyEntry.timestamp.desc(), ChainOfCustodyEntry.id.desc()).all()
            return [{"entry": entry, "evidence_number": evd_num} for entry, evd_num in rows]

    def add_custody_entry(
        self,
        case_id: int,
        evidence_id: int,
        action_type: str,
        delivered_by: str,
        received_by: str,
        location: str = "",
        acquire_method: str = "",
        write_blocker_info: str = "",
        sha256_at_event: str = "",
        sha512_at_event: str = "",
        verification_status: str = "Doğrulandı",
        notes: str = "",
    ) -> ChainOfCustodyEntry:
        """Append a Chain of Custody transfer/verification event and log it to AuditLog."""
        with self.Session() as s:
            evd = s.query(Evidence).filter(Evidence.id == evidence_id).first()
            if not evd:
                raise ValueError("İlgili delil kaydı bulunamadı.")

            entry = ChainOfCustodyEntry(
                case_id=case_id,
                evidence_id=evidence_id,
                timestamp=datetime.utcnow(),
                action_type=action_type.strip(),
                delivered_by=delivered_by.strip(),
                received_by=received_by.strip(),
                location=location.strip() or None,
                acquire_method=acquire_method.strip() or None,
                write_blocker_info=write_blocker_info.strip() or None,
                sha256_at_event=sha256_at_event.strip().lower() or evd.sha256_hash,
                sha512_at_event=sha512_at_event.strip().lower() or evd.sha512_hash,
                verification_status=verification_status,
                notes=notes.strip() or None,
            )
            s.add(entry)
            s.flush()

            s.add(AuditLog(
                case_id=case_id,
                investigator=received_by.strip() or "Adli Bilişim Uzmanı",
                action=f"Muhafaza Zinciri: {action_type}",
                details=f"{evd.evidence_number} ({delivered_by} -> {received_by}) | Durum: {verification_status}",
                verification_hash=(entry.sha256_at_event or "")[:32] or None,
            ))

            s.commit()
            s.refresh(entry)
            return entry
