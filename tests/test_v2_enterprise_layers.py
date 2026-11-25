"""Tests for v2.0 Enterprise DFIR Layers: Acquisition, RBAC Auth, X.509 Signing, Privilege & CR3 Kernel Header."""

import os
import struct
import pytest

from src.acquisition_engine.acquisition_service import AcquisitionService
from src.core.auth_service import AuthService
from src.core.privilege_service import PrivilegeService
from src.core.signing_service import SigningService
from src.memory_engine.memory_service import MemoryForensicsEngine


def test_acquisition_raw_and_split_verified(tmp_path):
    src_file = tmp_path / "source_disk.bin"
    payload = os.urandom(300 * 1024) + b"NTFS_FORENSIC_MARKER"
    src_file.write_bytes(payload)

    out_dd = tmp_path / "acquired.dd"
    man_single = AcquisitionService.acquire_raw_image(
        str(src_file),
        str(out_dd),
        write_blocker_verified=True,
        write_blocker_model="Tableau T8u",
        operator="E. Kırmızı",
    )
    assert man_single["post_verification_matched"] is True
    assert man_single["bytes_acquired"] == len(payload)
    assert os.path.isfile(str(out_dd) + ".acquisition.json")

    # Split 100KB test (note split_mb accepts MB; test 1MB split on 1.2MB file)
    big_src = tmp_path / "big_src.bin"
    big_src.write_bytes(os.urandom(1200 * 1024))
    out_split = tmp_path / "split.dd"
    man_split = AcquisitionService.acquire_raw_image(str(big_src), str(out_split), split_mb=1)
    assert man_split["segment_count"] == 2
    assert man_split["post_verification_matched"] is True
    assert len(AcquisitionService.list_storage_targets()) >= 1


def test_auth_rbac_and_pbkdf2_permissions(tmp_path):
    db_file = str(tmp_path / "rbac.db")
    auth = AuthService(db_path=db_file)
    users = auth.list_users()
    assert len(users) >= 4

    ok = auth.authenticate("e.kirmizi", "Forensic2026!")
    assert ok is not None and ok["role"] == "LeadInvestigator"
    assert auth.authenticate("e.kirmizi", "WrongPassword") is None

    assert AuthService.can_perform("LeadInvestigator", "sign_report") is True
    assert AuthService.can_perform("Reviewer", "sign_report") is False
    with pytest.raises(PermissionError):
        AuthService.require_permission("Reviewer", "archive_case")

    created = auth.create_user("yeni.analist", "Yeni Analist", "Analyst", "SecretPass99!")
    assert created["username"] == "yeni.analist"
    assert auth.authenticate("yeni.analist", "SecretPass99!")["role"] == "Analyst"


def test_x509_rsa_pss_report_signing_and_tamper_detection(tmp_path):
    cert_dir = str(tmp_path / "certs")
    pdf_fake = tmp_path / "adli_rapor.pdf"
    pdf_fake.write_bytes(b"%PDF-1.4\nForensic Report Content\n%%EOF")

    sig_doc = SigningService.sign_file(
        str(pdf_fake), signer_name="E. Kırmızı", signer_role="LeadInvestigator", cert_dir=cert_dir
    )
    assert os.path.isfile(sig_doc["signature_path"])

    ver_ok = SigningService.verify_signature(str(pdf_fake), sig_doc["signature_path"])
    assert ver_ok["valid"] is True
    assert ver_ok["hash_matched"] is True
    assert ver_ok["signature_crypto_valid"] is True

    # Tamper 1 byte of the report
    pdf_fake.write_bytes(b"%PDF-1.4\nTampered Report Content\n%%EOF")
    ver_bad = SigningService.verify_signature(str(pdf_fake), sig_doc["signature_path"])
    assert ver_bad["valid"] is False
    assert ver_bad["hash_matched"] is False


def test_privilege_status_and_pagedu64_kernel_header(tmp_path):
    st = PrivilegeService.get_status()
    assert "is_admin" in st and "guidance" in st

    # Construct DUMP_HEADER64 with non-zero CR3 & PsActiveProcessHead
    hdr = bytearray(4096)
    hdr[0:8] = b"PAGEDU64"
    struct.pack_into("<II", hdr, 8, 15, 22631)         # Major/Minor
    struct.pack_into("<Q", hdr, 16, 0x00000000001AD000) # DirectoryTableBase CR3
    struct.pack_into("<Q", hdr, 40, 0xFFFFF80012345678) # PsActiveProcessHead
    struct.pack_into("<III", hdr, 48, 0x8664, 8, 0xEF)  # Machine, 8 CPUs, BugCheck

    dmp = tmp_path / "kernel_hdr.dmp"
    dmp.write_bytes(bytes(hdr))
    res = MemoryForensicsEngine().inspect_memory_dump(str(dmp))
    assert res["header_details"]["DirectoryTableBase_CR3"] == "0x00000000001AD000"
    assert res["header_details"]["NumberOfProcessors"] == 8
    assert res["header_details"]["BugCheckCode"] == "0x000000EF"
