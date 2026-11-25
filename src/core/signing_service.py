"""Cryptographic X.509 RSA-PSS-SHA256 Report Signing & Independent Verification Service."""

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from typing import Any, Dict, Optional

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID


class SigningService:
    """Signs forensic exports (HTML/PDF/JSON) with an X.509 RSA-2048 certificate and verifies tamper resistance."""

    ALGORITHM = "RSA-PSS-SHA256 (X.509 v3)"

    @staticmethod
    def _sha256_file(path: str) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    @classmethod
    def ensure_lab_certificate(
        cls,
        cert_dir: str = "data/certs",
        common_name: str = "Adli Bilisim Inceleme Laboratuvari",
    ) -> Dict[str, Any]:
        """Load or generate an X.509 v3 RSA-2048 signing keypair & certificate."""
        os.makedirs(cert_dir, exist_ok=True)
        key_path = os.path.join(cert_dir, "lab_signing_key.pem")
        cert_path = os.path.join(cert_dir, "lab_signing_cert.pem")

        if os.path.isfile(key_path) and os.path.isfile(cert_path):
            with open(cert_path, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
            fp = cert.fingerprint(hashes.SHA256()).hex()
            return {
                "key_path": key_path,
                "cert_path": cert_path,
                "subject": cert.subject.rfc4514_string(),
                "fingerprint_sha256": fp,
                "serial_number": hex(cert.serial_number),
                "not_after_utc": cert.not_valid_after_utc.isoformat(),
            }

        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        now = datetime.now(timezone.utc)
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "TR"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Adli Bilisim DFIR Lab"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(private_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=1))
            .not_valid_after(now + timedelta(days=1095))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .sign(private_key, hashes.SHA256())
        )

        with open(key_path, "wb") as f:
            f.write(
                private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))

        return {
            "key_path": key_path,
            "cert_path": cert_path,
            "subject": cert.subject.rfc4514_string(),
            "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "serial_number": hex(cert.serial_number),
            "not_after_utc": cert.not_valid_after_utc.isoformat(),
        }

    @classmethod
    def sign_file(
        cls,
        file_path: str,
        signer_name: str,
        signer_role: str = "LeadInvestigator",
        cert_dir: str = "data/certs",
        sig_out_path: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Create a detached cryptographic X.509 RSA-PSS-SHA256 signature bundle (.sig.json)."""
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"İmzalanacak dosya bulunamadı: {file_path}")

        cert_info = cls.ensure_lab_certificate(cert_dir=cert_dir)
        with open(cert_info["key_path"], "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
        with open(cert_info["cert_path"], "rb") as f:
            cert_pem = f.read().decode("utf-8")

        file_sha256 = cls._sha256_file(file_path)
        signed_at = datetime.now(timezone.utc).isoformat()
        canonical_manifest = f"{os.path.basename(file_path)}|{file_sha256}|{signer_name}|{signer_role}|{signed_at}"

        sig_bytes = priv.sign(
            canonical_manifest.encode("utf-8"),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )

        sig_doc = {
            "schema": "adli-bilisim-x509-sig/v1",
            "algorithm": cls.ALGORITHM,
            "target_filename": os.path.basename(file_path),
            "target_size_bytes": os.path.getsize(file_path),
            "file_sha256": file_sha256,
            "signer_name": signer_name,
            "signer_role": signer_role,
            "signed_at_utc": signed_at,
            "canonical_payload": canonical_manifest,
            "signature_b64": base64.b64encode(sig_bytes).decode("ascii"),
            "cert_subject": cert_info["subject"],
            "cert_fingerprint_sha256": cert_info["fingerprint_sha256"],
            "certificate_pem": cert_pem,
        }

        out_p = sig_out_path or (file_path + ".sig.json")
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(sig_doc, f, indent=2, ensure_ascii=False)
        sig_doc["signature_path"] = out_p
        return sig_doc

    @classmethod
    def verify_signature(cls, file_path: str, sig_path: Optional[str] = None) -> Dict[str, Any]:
        """Independently verify file SHA-256 and RSA-PSS X.509 cryptographic signature."""
        sp = sig_path or (file_path + ".sig.json")
        if not os.path.isfile(file_path):
            raise FileNotFoundError(f"Hedef dosya bulunamadı: {file_path}")
        if not os.path.isfile(sp):
            raise FileNotFoundError(f"İmza dosyası bulunamadı: {sp}")

        with open(sp, "r", encoding="utf-8") as f:
            doc = json.load(f)

        actual_sha256 = cls._sha256_file(file_path)
        expected_sha256 = doc.get("file_sha256", "")
        hash_ok = actual_sha256 == expected_sha256

        cert = x509.load_pem_x509_certificate(doc["certificate_pem"].encode("utf-8"))
        pub = cert.public_key()
        sig_bytes = base64.b64decode(doc["signature_b64"])
        payload = doc["canonical_payload"].encode("utf-8")

        crypto_ok = False
        error_msg = ""
        try:
            pub.verify(
                sig_bytes,
                payload,
                padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
                hashes.SHA256(),
            )
            crypto_ok = True
        except Exception as exc:
            error_msg = str(exc)

        valid = bool(hash_ok and crypto_ok and (expected_sha256 in doc["canonical_payload"]))
        return {
            "valid": valid,
            "hash_matched": hash_ok,
            "signature_crypto_valid": crypto_ok,
            "expected_sha256": expected_sha256,
            "actual_sha256": actual_sha256,
            "signer_name": doc.get("signer_name"),
            "signer_role": doc.get("signer_role"),
            "signed_at_utc": doc.get("signed_at_utc"),
            "cert_fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
            "error": error_msg,
        }
