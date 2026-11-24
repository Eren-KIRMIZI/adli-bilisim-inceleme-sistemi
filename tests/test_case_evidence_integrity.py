"""Unit tests for CaseService, EvidenceService, and IntegrityService."""

import pytest
from src.case_engine.case_service import CaseService
from src.evidence_engine.evidence_service import EvidenceService
from src.integrity_engine.integrity_service import IntegrityService


@pytest.fixture
def services(tmp_path):
    db_file = str(tmp_path / "test_suite.db")
    return (
        CaseService(db_path=db_file),
        EvidenceService(db_path=db_file),
        IntegrityService(db_path=db_file),
        tmp_path,
    )


def test_case_lifecycle(services):
    case_svc, _, _, _ = services
    c = case_svc.create_case("VAK-TEST-100", "Test Adli Soruşturma", "Uzman A", "Açıklama", organization="Siber Birim")
    assert c.id is not None
    assert c.status == "open"

    # Duplicate case number must raise ValueError
    with pytest.raises(ValueError):
        case_svc.create_case("VAK-TEST-100", "Duplicate")

    # Update status to closed
    updated = case_svc.update_case(c.id, status="closed")
    assert updated.status == "closed"
    assert updated.closed_at is not None

    summary = case_svc.get_case_summary(c.id)
    assert len(summary["audit_logs"]) >= 2


def test_evidence_and_custody_creation(services):
    case_svc, evd_svc, int_svc, tmp_path = services
    c = case_svc.create_case("VAK-TEST-200", "Delil Test Vakası", "Uzman B")

    # Create dummy evidence file
    sample_file = tmp_path / "disk_image.bin"
    sample_file.write_bytes(b"FORENSIC_EVIDENCE_PAYLOAD_001")

    hashes = IntegrityService.compute_dual_hashes(str(sample_file))
    assert len(hashes["sha256"]) == 64
    assert len(hashes["sha512"]) == 128

    evd = evd_svc.add_evidence(
        case_id=c.id,
        device_type="Disk İmajı",
        brand="Western Digital",
        model="WD Blue 1TB",
        serial="WCC12345",
        custodian="Uzman B",
        write_blocker_used=True,
        sha256_hash=hashes["sha256"],
        sha512_hash=hashes["sha512"],
        file_path=str(sample_file),
    )
    assert evd.evidence_number.startswith("EVD-")
    assert evd.status == "verified"

    # Verify initial Chain of Custody record was created
    cust_records = int_svc.list_custody_records(evidence_id=evd.id)
    assert len(cust_records) == 1
    assert cust_records[0]["entry"].verification_status == "Doğrulandı"

    # Verify detailed hash check
    v_ok = IntegrityService.verify_detailed(str(sample_file), hashes["sha256"])
    assert v_ok["matched"] is True

    v_fail = IntegrityService.verify_detailed(str(sample_file), "0" * 64)
    assert v_fail["matched"] is False
