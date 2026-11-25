"""USB Hardware-Token Cryptographic Authentication Service (Ed25519 Challenge-Response + PBKDF2 2FA).

Security design:
- Step 1 (USB Key): Detects removable/registered USB drive (e.g., Key D:), issues a fresh 32-byte
  random challenge, signs it with the Ed25519 private key stored on the USB (.forensic_key/),
  and verifies the signature against the locally registered Ed25519 public key.
- Step 2 (Personal Security Password): Verifies user-chosen password via PBKDF2-HMAC-SHA256
  (200,000 iterations + random salt) using constant-time comparison, enforces temporary lockout
  after consecutive failures, and records all attempts in the hash-chained AuditLog.
"""

import ctypes
from ctypes import wintypes
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
import secrets
import time
from typing import Any, Dict, List, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from src.database.models import init_db, append_audit_log
from src.database.seed import seed_database_if_empty


class UsbCryptoAuthService:
    """Two-factor USB cryptographic challenge-response + personal password authenticator."""

    KEY_FOLDER_NAME = ".forensic_key"
    PRIVATE_KEY_FILENAME = "usb_private_key.pem"
    KEY_META_FILENAME = "usb_key_info.json"
    PBKDF2_ITERATIONS = 200_000
    MAX_FAILED_ATTEMPTS = 5
    LOCKOUT_SECONDS = 30

    def __init__(
        self,
        config_path: str = "data/usb_auth.json",
        db_path: str = "data/forensics.db",
        custom_usb_roots: Optional[List[str]] = None,
    ):
        self.config_path = config_path
        self.db_path = db_path
        self.custom_usb_roots = custom_usb_roots
        self.Session = init_db(db_path)
        seed_database_if_empty(db_path)

    def is_provisioned(self) -> bool:
        if not os.path.isfile(self.config_path):
            return False
        try:
            cfg = self._load_config()
            return bool(cfg.get("public_key_pem") and cfg.get("password_hash_hex"))
        except Exception:
            return False

    def _load_config(self) -> Dict[str, Any]:
        if not os.path.isfile(self.config_path):
            return {}
        with open(self.config_path, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_config(self, cfg: Dict[str, Any]) -> None:
        os.makedirs(os.path.dirname(os.path.abspath(self.config_path)) or ".", exist_ok=True)
        tmp = self.config_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, self.config_path)

    @classmethod
    def _hash_password(cls, password: str, salt_hex: Optional[str] = None) -> tuple[str, str]:
        salt = bytes.fromhex(salt_hex) if salt_hex else secrets.token_bytes(16)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, cls.PBKDF2_ITERATIONS)
        return salt.hex(), dk.hex()

    @staticmethod
    def _format_serial(serial_int: int) -> str:
        hi = (serial_int >> 16) & 0xFFFF
        lo = serial_int & 0xFFFF
        return f"{hi:04X}-{lo:04X}"

    def detect_usb_drives(self) -> List[Dict[str, Any]]:
        """Enumerate connected USB/removable drives (or custom test roots) and check key presence."""
        found: List[Dict[str, Any]] = []
        if self.custom_usb_roots is not None:
            for root in self.custom_usb_roots:
                if os.path.isdir(root):
                    key_p = os.path.join(root, self.KEY_FOLDER_NAME, self.PRIVATE_KEY_FILENAME)
                    meta_p = os.path.join(root, self.KEY_FOLDER_NAME, self.KEY_META_FILENAME)
                    meta = {}
                    if os.path.isfile(meta_p):
                        try:
                            meta = json.loads(open(meta_p, "r", encoding="utf-8").read())
                        except Exception:
                            meta = {}
                    found.append({
                        "root": root,
                        "drive_letter": meta.get("drive_letter", "USB:"),
                        "label": meta.get("label", "Key"),
                        "serial": meta.get("volume_serial", "TEST-USB1"),
                        "capacity_gb": meta.get("capacity_gb", "28.9 GB"),
                        "has_key_file": os.path.isfile(key_p),
                        "key_path": key_p,
                        "meta": meta,
                    })
            return found

        if os.name == "nt" and hasattr(ctypes, "windll"):
            k32 = ctypes.windll.kernel32
            bitmask = k32.GetLogicalDrives()
            for i in range(26):
                if not (bitmask & (1 << i)):
                    continue
                letter = chr(ord("A") + i)
                root = f"{letter}:\\"
                dtype = k32.GetDriveTypeW(root)
                key_p = os.path.join(root, self.KEY_FOLDER_NAME, self.PRIVATE_KEY_FILENAME)
                has_key = os.path.isfile(key_p)
                # Accept Removable drives (2) OR Fixed USB drives that carry .forensic_key
                if dtype != 2 and not (dtype == 3 and has_key):
                    continue

                vol_name = ctypes.create_unicode_buffer(261)
                fs_name = ctypes.create_unicode_buffer(261)
                serial_no = wintypes.DWORD(0)
                k32.GetVolumeInformationW(
                    root, vol_name, 260, ctypes.byref(serial_no), None, None, fs_name, 260
                )
                avail = ctypes.c_ulonglong(0)
                total = ctypes.c_ulonglong(0)
                free = ctypes.c_ulonglong(0)
                k32.GetDiskFreeSpaceExW(root, ctypes.byref(avail), ctypes.byref(total), ctypes.byref(free))
                cap_gb = f"{total.value / (1024 ** 3):.1f} GB" if total.value else "-"

                meta_p = os.path.join(root, self.KEY_FOLDER_NAME, self.KEY_META_FILENAME)
                meta = {}
                if os.path.isfile(meta_p):
                    try:
                        with open(meta_p, "r", encoding="utf-8") as mf:
                            meta = json.load(mf)
                    except Exception:
                        meta = {}

                found.append({
                    "root": root,
                    "drive_letter": f"{letter}:",
                    "label": vol_name.value or meta.get("label", "USB"),
                    "serial": self._format_serial(serial_no.value),
                    "capacity_gb": cap_gb,
                    "has_key_file": has_key,
                    "key_path": key_p,
                    "meta": meta,
                })
        return found

    def provision_usb_key(
        self,
        usb_root: str,
        personal_password: str,
        operator_name: str = "Adli Bilişim Uzmanı E. Kırmızı",
        operator_role: str = "LeadInvestigator",
        allow_overwrite: bool = False,
    ) -> Dict[str, Any]:
        """Generate an Ed25519 keypair on the target USB drive and store public key + PBKDF2 password hash locally."""
        if self.is_provisioned() and not allow_overwrite:
            raise PermissionError("Sistem zaten bir USB güvenlik anahtarına bağlı. Üzerine yazma engellendi.")
        if not os.path.isdir(usb_root):
            raise FileNotFoundError(f"Hedef USB dizini bulunamadı: {usb_root}")
        if not personal_password or len(personal_password) < 6:
            raise ValueError("Kişisel güvenlik şifresi en az 6 karakter olmalıdır.")

        # Collect drive metadata
        drive_letter = usb_root[:2].upper() if len(usb_root) >= 2 and usb_root[1] == ":" else "USB:"
        label = "Key"
        serial_str = "USB-KEY-01"
        cap_gb = "-"
        if os.name == "nt" and hasattr(ctypes, "windll") and len(usb_root) >= 2 and usb_root[1] == ":":
            k32 = ctypes.windll.kernel32
            root_norm = drive_letter + "\\"
            vol_name = ctypes.create_unicode_buffer(261)
            fs_name = ctypes.create_unicode_buffer(261)
            serial_no = wintypes.DWORD(0)
            if k32.GetVolumeInformationW(root_norm, vol_name, 260, ctypes.byref(serial_no), None, None, fs_name, 260):
                label = vol_name.value or label
                serial_str = self._format_serial(serial_no.value)
            avail, total, free = ctypes.c_ulonglong(0), ctypes.c_ulonglong(0), ctypes.c_ulonglong(0)
            if k32.GetDiskFreeSpaceExW(root_norm, ctypes.byref(avail), ctypes.byref(total), ctypes.byref(free)) and total.value:
                cap_gb = f"{total.value / (1024 ** 3):.1f} GB"

        priv_key = Ed25519PrivateKey.generate()
        pub_key = priv_key.public_key()
        priv_pem = priv_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode("ascii")
        pub_pem = pub_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("ascii")

        key_id = f"KEY-ED25519-{secrets.token_hex(6).upper()}"
        key_dir = os.path.join(usb_root, self.KEY_FOLDER_NAME)
        os.makedirs(key_dir, exist_ok=True)
        with open(os.path.join(key_dir, self.PRIVATE_KEY_FILENAME), "w", encoding="ascii") as kf:
            kf.write(priv_pem)
        with open(os.path.join(key_dir, self.KEY_META_FILENAME), "w", encoding="utf-8") as mf:
            json.dump({
                "key_id": key_id,
                "label": label,
                "drive_letter": drive_letter,
                "volume_serial": serial_str,
                "capacity_gb": cap_gb,
                "algorithm": "Ed25519",
                "created_at_utc": datetime.now(timezone.utc).isoformat(),
            }, mf, indent=2, ensure_ascii=False)

        # Hide .forensic_key folder cleanly on Windows
        if os.name == "nt" and hasattr(ctypes, "windll"):
            try:
                ctypes.windll.kernel32.SetFileAttributesW(key_dir, 0x02)  # FILE_ATTRIBUTE_HIDDEN
            except Exception:
                pass

        salt_hex, pwd_hash_hex = self._hash_password(personal_password)
        cfg = {
            "schema": "adli-bilisim-usb-auth/v1",
            "key_id": key_id,
            "algorithm": "Ed25519",
            "expected_label": label,
            "expected_drive": drive_letter,
            "expected_volume_serial": serial_str,
            "public_key_pem": pub_pem,
            "password_salt_hex": salt_hex,
            "password_hash_hex": pwd_hash_hex,
            "failed_attempts": 0,
            "lockout_until_epoch": 0.0,
            "operator_name": operator_name,
            "operator_role": operator_role,
            "provisioned_at_utc": datetime.now(timezone.utc).isoformat(),
        }
        self._save_config(cfg)
        self._audit("USB Güvenlik Anahtarı Kaydedildi", f"{label} ({drive_letter}) | {key_id} | Ed25519")
        return {
            "key_id": key_id,
            "label": label,
            "drive_letter": drive_letter,
            "volume_serial": serial_str,
            "capacity_gb": cap_gb,
        }

    def verify_usb_challenge(self, preferred_root: Optional[str] = None) -> Dict[str, Any]:
        """Perform Step 1: detect USB key and execute live Ed25519 cryptographic challenge-response."""
        if not self.is_provisioned():
            return {
                "verified": False,
                "state": "NO_PROVISION",
                "message": "Kayıtlı USB güvenlik anahtarı bulunamadı. İlk kurulumu yapın.",
                "drive_letter": "-",
                "volume_label": "-",
                "capacity_gb": "-",
                "key_id": "-",
                "challenge_hex": "-",
                "signature_hex": "-",
            }

        cfg = self._load_config()
        drives = self.detect_usb_drives()
        if preferred_root:
            drives = [d for d in drives if os.path.normpath(d["root"]) == os.path.normpath(preferred_root)]

        key_drives = [d for d in drives if d.get("has_key_file")]
        if not key_drives:
            if drives:
                d0 = drives[0]
                return {
                    "verified": False,
                    "state": "USB_NO_KEY",
                    "message": f"USB ({d0['label']} {d0['drive_letter']}) algılandı ancak kriptografik anahtar dosyası bulunamadı.",
                    "drive_letter": d0["drive_letter"],
                    "volume_label": d0["label"],
                    "capacity_gb": d0["capacity_gb"],
                    "key_id": "-",
                    "challenge_hex": "-",
                    "signature_hex": "-",
                }
            return {
                "verified": False,
                "state": "WAITING_USB",
                "message": "Güvenlik anahtarınızı takın (Key D: bekleniyor)...",
                "drive_letter": "-",
                "volume_label": "-",
                "capacity_gb": "-",
                "key_id": "-",
                "challenge_hex": "-",
                "signature_hex": "-",
            }

        pub_key = serialization.load_pem_public_key(cfg["public_key_pem"].encode("ascii"))
        if not isinstance(pub_key, Ed25519PublicKey):
            return {"verified": False, "state": "CHALLENGE_FAILED", "message": "Kayıtlı açık anahtar Ed25519 değil."}

        challenge = os.urandom(32)
        for drv in key_drives:
            try:
                with open(drv["key_path"], "rb") as kf:
                    priv_key = serialization.load_pem_private_key(kf.read(), password=None)
                if not isinstance(priv_key, Ed25519PrivateKey):
                    continue
                signature = priv_key.sign(challenge)
                pub_key.verify(signature, challenge)
                return {
                    "verified": True,
                    "state": "SIGNATURE_VERIFIED",
                    "message": "DİJİTAL İMZA DOĞRULANDI",
                    "drive_letter": drv["drive_letter"],
                    "volume_label": drv["label"],
                    "volume_serial": drv["serial"],
                    "capacity_gb": drv["capacity_gb"],
                    "key_id": drv.get("meta", {}).get("key_id", cfg.get("key_id", "-")),
                    "challenge_hex": challenge[:8].hex().upper(),
                    "signature_hex": signature[:8].hex().upper(),
                    "root": drv["root"],
                }
            except Exception:
                continue

        self._audit("USB Kriptografik İmza Hatası", "Takılı USB üzerindeki özel anahtar kayıtlı açık anahtarla eşleşmedi.")
        return {
            "verified": False,
            "state": "CHALLENGE_FAILED",
            "message": "USB kriptografik imza doğrulaması reddedildi (geçersiz veya kopya anahtar).",
            "drive_letter": key_drives[0]["drive_letter"],
            "volume_label": key_drives[0]["label"],
            "capacity_gb": key_drives[0]["capacity_gb"],
            "key_id": "-",
            "challenge_hex": challenge[:8].hex().upper(),
            "signature_hex": "-",
        }

    def get_lockout_remaining(self) -> int:
        if not self.is_provisioned():
            return 0
        cfg = self._load_config()
        rem = int(cfg.get("lockout_until_epoch", 0.0) - time.time())
        return max(0, rem)

    def verify_personal_password(self, password: str, usb_verified: bool) -> Dict[str, Any]:
        """Perform Step 2: verify personal security password with lockout & audit logging."""
        if not usb_verified:
            return {"authenticated": False, "locked": False, "reason": "Önce USB kriptografik imza doğrulaması gereklidir."}
        if not self.is_provisioned():
            return {"authenticated": False, "locked": False, "reason": "Sistemde kayıtlı USB anahtarı yok."}

        rem = self.get_lockout_remaining()
        if rem > 0:
            return {
                "authenticated": False,
                "locked": True,
                "remaining_seconds": rem,
                "reason": f"Çok fazla hatalı deneme. Sistem {rem} saniye kilitli.",
            }

        cfg = self._load_config()
        _, cand_hex = self._hash_password(password or "", salt_hex=cfg["password_salt_hex"])
        if hmac.compare_digest(cand_hex, cfg["password_hash_hex"]):
            cfg["failed_attempts"] = 0
            cfg["lockout_until_epoch"] = 0.0
            self._save_config(cfg)
            token = secrets.token_hex(24)
            op_name = cfg.get("operator_name", "Adli Bilişim Uzmanı")
            op_role = cfg.get("operator_role", "LeadInvestigator")
            self._audit(
                "USB-2FA Güvenli Oturum Başlatıldı",
                f"Operatör: {op_name} ({op_role}) | Anahtar: {cfg.get('key_id', '-')}",
                investigator=op_name,
            )
            return {
                "authenticated": True,
                "locked": False,
                "session_token": token,
                "operator_name": op_name,
                "operator_role": op_role,
                "key_id": cfg.get("key_id", "-"),
            }

        fails = int(cfg.get("failed_attempts", 0)) + 1
        cfg["failed_attempts"] = fails
        locked = False
        rem_sec = 0
        if fails >= self.MAX_FAILED_ATTEMPTS:
            cfg["lockout_until_epoch"] = time.time() + self.LOCKOUT_SECONDS
            cfg["failed_attempts"] = 0
            locked = True
            rem_sec = self.LOCKOUT_SECONDS
        self._save_config(cfg)
        self._audit(
            "USB-2FA Başarısız Şifre Denemesi",
            f"Hatalı kişisel şifre (Deneme {fails}/{self.MAX_FAILED_ATTEMPTS}) | Kilit: {locked}",
        )
        return {
            "authenticated": False,
            "locked": locked,
            "remaining_seconds": rem_sec,
            "failed_attempts": fails,
            "max_attempts": self.MAX_FAILED_ATTEMPTS,
            "reason": (
                f"5 hatalı deneme! Güvenlik kilidi etkin ({self.LOCKOUT_SECONDS} sn)."
                if locked else f"Hatalı kişisel güvenlik şifresi ({fails}/{self.MAX_FAILED_ATTEMPTS})."
            ),
        }

    def _audit(self, action: str, details: str, investigator: str = "USB-AuthGate") -> None:
        try:
            with self.Session() as s:
                append_audit_log(s, None, investigator, action, details)
                s.commit()
        except Exception:
            pass
