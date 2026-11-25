"""Analyst Finding Bookmarking & Tagging Service (Kanıt / Şüpheli / Kritik IOC / Yanlış Pozitif)."""

from typing import Any, Dict, List, Optional
from src.database.models import init_db, ArtifactBookmark, append_audit_log
from src.database.seed import seed_database_if_empty


class BookmarkService:
    """Persists analyst-curated bookmarks & tags for inclusion in forensic reports."""

    VALID_TAGS = ("Kanıt", "Şüpheli", "Kritik IOC", "Yanlış Pozitif")

    def __init__(self, db_path: str = "data/forensics.db"):
        self.db_path = db_path
        self.Session = init_db(db_path)
        seed_database_if_empty(db_path)

    def add_bookmark(
        self,
        case_id: int,
        tag: str,
        source_module: str,
        item_label: str,
        item_reference: str = "",
        analyst_note: str = "",
        analyst_name: str = "Adli Bilişim Uzmanı",
    ) -> ArtifactBookmark:
        chosen_tag = tag if tag in self.VALID_TAGS else "Şüpheli"
        with self.Session() as s:
            bm = ArtifactBookmark(
                case_id=case_id,
                tag=chosen_tag,
                source_module=source_module,
                item_label=item_label[:255],
                item_reference=item_reference[:512],
                analyst_note=analyst_note,
                analyst_name=analyst_name,
            )
            s.add(bm)
            append_audit_log(s, case_id, analyst_name, f"Bulgu Etiketlendi ({chosen_tag})", f"[{source_module}] {item_label}")
            s.commit()
            s.refresh(bm)
            return bm

    def list_bookmarks(self, case_id: Optional[int] = None) -> List[ArtifactBookmark]:
        with self.Session() as s:
            q = s.query(ArtifactBookmark)
            if case_id is not None:
                q = q.filter(ArtifactBookmark.case_id == case_id)
            return q.order_by(ArtifactBookmark.created_at.desc()).all()

    def delete_bookmark(self, bookmark_id: int) -> bool:
        with self.Session() as s:
            bm = s.query(ArtifactBookmark).filter(ArtifactBookmark.id == bookmark_id).first()
            if not bm:
                return False
            s.delete(bm)
            s.commit()
            return True
