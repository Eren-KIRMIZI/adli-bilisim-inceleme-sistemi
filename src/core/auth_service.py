"""Institutional Multi-User RBAC & PBKDF2-HMAC-SHA256 Authentication Service."""

import hashlib
import hmac
import secrets
from typing import Any, Dict, List, Optional

from src.database.models import init_db, UserAccount, append_audit_log

ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "Admin": [
        "view", "create_case", "archive_case", "acquire_evidence",
        "verify_hash", "add_custody", "analyze", "export_report",
        "sign_report", "manage_users",
    ],
    "LeadInvestigator": [
        "view", "create_case", "archive_case", "acquire_evidence",
        "verify_hash", "add_custody", "analyze", "export_report",
        "sign_report",
    ],
    "Analyst": [
        "view", "acquire_evidence", "verify_hash", "add_custody",
        "analyze", "export_report",
    ],
    "Reviewer": [
        "view", "verify_hash", "export_report",
    ],
}

ROLE_LABELS_TR: Dict[str, str] = {
    "Admin": "Laboratuvar Yöneticisi (Admin)",
    "LeadInvestigator": "Kıdemli Adli Uzman (Lead)",
    "Analyst": "Adli Analist (Analyst)",
    "Reviewer": "Denetçi / Salt-Okunur (Reviewer)",
}

DEFAULT_DEMO_USERS = [
    ("e.kirmizi", "Adli Bilişim Uzmanı E. Kırmızı", "LeadInvestigator", "Forensic2026!"),
    ("lab.admin", "Laboratuvar Amiri M. Demir", "Admin", "Admin2026!"),
    ("a.analist", "Dijital Delil Analisti Z. Kaya", "Analyst", "Analyst2026!"),
    ("denetci", "Bağımsız Denetçi R. Yılmaz", "Reviewer", "Review2026!"),
]


class AuthService:
    """Manages laboratory analysts, PBKDF2 password verification, and strict RBAC enforcement."""

    PBKDF2_ITERATIONS = 200_000

    def __init__(self, db_path: str = "data/forensics.db"):
        self.db_path = db_path
        self.Session = init_db(db_path)
        self.ensure_default_users()

    @classmethod
    def _hash_password(cls, password: str, salt_hex: Optional[str] = None) -> tuple[str, str]:
        salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, cls.PBKDF2_ITERATIONS)
        return salt.hex(), dk.hex()

    def ensure_default_users(self) -> None:
        with self.Session() as s:
            if s.query(UserAccount).first() is not None:
                return
            for uname, fname, role, pwd in DEFAULT_DEMO_USERS:
                salt_h, pwd_h = self._hash_password(pwd)
                s.add(UserAccount(
                    username=uname,
                    full_name=fname,
                    role=role,
                    salt=salt_h,
                    password_hash=pwd_h,
                    is_active=True,
                ))
            s.commit()

    def list_users(self) -> List[Dict[str, Any]]:
        with self.Session() as s:
            rows = s.query(UserAccount).order_by(UserAccount.id.asc()).all()
            return [
                {
                    "id": u.id,
                    "username": u.username,
                    "full_name": u.full_name,
                    "role": u.role,
                    "role_tr": ROLE_LABELS_TR.get(u.role, u.role),
                    "permissions": ", ".join(ROLE_PERMISSIONS.get(u.role, [])),
                    "is_active": bool(u.is_active),
                }
                for u in rows
            ]

    def create_user(
        self,
        username: str,
        full_name: str,
        role: str,
        password: str,
        actor_name: str = "Admin",
    ) -> Dict[str, Any]:
        if role not in ROLE_PERMISSIONS:
            raise ValueError(f"Geçersiz rol: {role}")
        if not username.strip() or len(password) < 6:
            raise ValueError("Kullanıcı adı boş olamaz ve parola en az 6 karakter olmalıdır.")
        with self.Session() as s:
            existing = s.query(UserAccount).filter(UserAccount.username == username.strip()).first()
            if existing:
                raise ValueError(f"Bu kullanıcı adı zaten kayıtlı: {username}")
            salt_h, pwd_h = self._hash_password(password)
            user = UserAccount(
                username=username.strip(),
                full_name=full_name.strip() or username.strip(),
                role=role,
                salt=salt_h,
                password_hash=pwd_h,
                is_active=True,
            )
            s.add(user)
            append_audit_log(
                s,
                None,
                actor_name,
                "Kullanıcı Oluşturuldu (RBAC)",
                f"Kullanıcı={user.username} | Rol={user.role}",
            )
            s.commit()
            return {"id": user.id, "username": user.username, "full_name": user.full_name, "role": user.role}

    def authenticate(self, username: str, password: str) -> Optional[Dict[str, Any]]:
        with self.Session() as s:
            user = s.query(UserAccount).filter(UserAccount.username == username.strip()).first()
            if not user or not user.is_active:
                return None
            _, cand_hash = self._hash_password(password, user.salt)
            if hmac.compare_digest(cand_hash, user.password_hash):
                append_audit_log(
                    s,
                    None,
                    user.full_name,
                    "Oturum Değişikliği (RBAC)",
                    f"Aktif oturum doğrulandı: {user.username} ({user.role})",
                )
                s.commit()
                return {
                    "id": user.id,
                    "username": user.username,
                    "full_name": user.full_name,
                    "role": user.role,
                    "role_tr": ROLE_LABELS_TR.get(user.role, user.role),
                }
            return None

    @staticmethod
    def can_perform(role: str, action: str) -> bool:
        return action in ROLE_PERMISSIONS.get(role, [])

    @classmethod
    def require_permission(cls, role: str, action: str) -> None:
        if not cls.can_perform(role, action):
            raise PermissionError(
                f"Yetkisiz işlem (RBAC): '{role}' rolü '{action}' yetkisine sahip değil."
            )
