"""Crash & Power-Loss Recovery, Atomic Session Checkpointing, and Verified SQLite Backups."""

import hashlib
import json
import os
import sqlite3
from datetime import datetime
from typing import Any, Dict, Optional


class RecoveryManager:
    """Protects investigator workspace state against sudden power loss or crashes."""

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        os.makedirs(self.data_dir, exist_ok=True)
        self.lock_file = os.path.join(self.data_dir, ".session_active.lock")
        self.state_file = os.path.join(self.data_dir, "session_recovery.json")
        self.backup_dir = os.path.join(self.data_dir, "backups")
        self.unclean_shutdown_detected = False
        self.recovered_state: Dict[str, Any] = {}

    def begin_session(self) -> Dict[str, Any]:
        """Detect previous unclean shutdown and load last atomic checkpoint if present."""
        if os.path.exists(self.lock_file):
            self.unclean_shutdown_detected = True
        self.recovered_state = self.load_checkpoint()

        # Write active lock marker atomically
        self._atomic_write_text(
            self.lock_file,
            json.dumps({"started_at": datetime.utcnow().isoformat() + "Z", "pid": os.getpid()}),
        )
        return self.recovered_state

    def save_checkpoint(
        self,
        active_case_id: Optional[int] = None,
        active_evidence_id: Optional[int] = None,
        page_index: int = 0,
        theme: str = "light",
        report_draft: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Persist current workspace state atomically with fsync."""
        payload = {
            "saved_at": datetime.utcnow().isoformat() + "Z",
            "active_case_id": active_case_id,
            "active_evidence_id": active_evidence_id,
            "page_index": page_index,
            "theme": theme,
            "report_draft": report_draft or {},
        }
        self._atomic_write_text(self.state_file, json.dumps(payload, indent=2, ensure_ascii=False))

    def load_checkpoint(self) -> Dict[str, Any]:
        """Load last saved session checkpoint safely."""
        if not os.path.isfile(self.state_file):
            return {}
        try:
            with open(self.state_file, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def end_session_cleanly(self) -> None:
        """Remove active lock marker on normal application exit."""
        try:
            if os.path.exists(self.lock_file):
                os.remove(self.lock_file)
        except OSError:
            pass

    def create_verified_db_backup(self, db_path: str = "data/forensics.db", max_keep: int = 5) -> Optional[str]:
        """Create a consistent online SQLite backup + SHA-256 verification file."""
        if not os.path.isfile(db_path):
            return None
        os.makedirs(self.backup_dir, exist_ok=True)
        stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(self.backup_dir, f"forensics_backup_{stamp}.db")

        src_con = sqlite3.connect(db_path)
        dst_con = sqlite3.connect(backup_path)
        try:
            src_con.backup(dst_con)
        finally:
            dst_con.close()
            src_con.close()

        # Write SHA-256 verification sidecar
        h = hashlib.sha256()
        with open(backup_path, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        with open(backup_path + ".sha256", "w", encoding="utf-8") as sf:
            sf.write(f"{h.hexdigest()}  {os.path.basename(backup_path)}\n")

        # Prune older backups beyond max_keep
        backups = sorted(
            f for f in os.listdir(self.backup_dir) if f.startswith("forensics_backup_") and f.endswith(".db")
        )
        while len(backups) > max_keep:
            oldest = backups.pop(0)
            for ext in ("", ".sha256"):
                p = os.path.join(self.backup_dir, oldest + ext)
                if os.path.exists(p):
                    os.remove(p)

        return backup_path

    @staticmethod
    def _atomic_write_text(target_path: str, content: str) -> None:
        tmp_path = target_path + ".tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(content)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_path, target_path)
