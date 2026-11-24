"""Unit tests for Core Pydantic model, TimelineService, CorrelationService, and ReportService."""

from datetime import datetime
from src.core.models import ForensicArtifactModel
from src.timeline_engine.timeline_service import TimelineService
from src.correlation_engine.correlation_service import CorrelationService
from src.report_engine.report_service import ReportService


def test_core_forensic_artifact_model():
    m = ForensicArtifactModel(
        artifact_id="ART-001",
        case_id=1,
        evidence_id=1,
        artifact_type="USB",
        source_file="SYSTEM",
        source_location=r"Enum\USBSTOR",
        extracted_data={"vid": "0781", "pid": "5567"},
        original_timestamp="2026-11-20T12:00:00Z",
        normalized_timestamp=datetime(2026, 11, 20, 12, 0, 0),
        parser_name="UsbService",
        parser_version="1.0.0",
        confidence=100,
    )
    assert m.artifact_id == "ART-001"
    assert m.confidence == 100


def test_timeline_service_and_delta(tmp_path):
    db_file = str(tmp_path / "tl.db")
    tl = TimelineService(db_path=db_file)
    events = tl.collect_case_timeline()
    assert len(events) >= 10
    # Ensure chronological sort
    timestamps = [e["timestamp_utc"] for e in events if e["timestamp_utc"]]
    assert timestamps == sorted(timestamps)

    delta = TimelineService.compute_time_delta(datetime(2026, 11, 20, 10, 0, 0), datetime(2026, 11, 20, 12, 15, 30))
    assert "2 saat" in delta and "15 dk" in delta and "30 sn" in delta


def test_correlation_graph_verified_vs_hypotheses(tmp_path):
    db_file = str(tmp_path / "corr.db")
    corr = CorrelationService(db_path=db_file)

    g_with = corr.build_case_graph(include_hypotheses=True)
    assert len(g_with["nodes"]) >= 6
    assert any(e["verified"] for e in g_with["edges"])
    assert any(not e["verified"] for e in g_with["edges"])

    g_only_verified = corr.build_case_graph(include_hypotheses=False)
    assert all(e["verified"] for e in g_only_verified["edges"])


def test_report_service_html_and_pdf(tmp_path):
    db_file = str(tmp_path / "rep.db")
    rsvc = ReportService(db_path=db_file)

    html_path = str(tmp_path / "forensic_report.html")
    rsvc.export_html(html_path, expert_notes="Test uzman notu")
    with open(html_path, "r", encoding="utf-8") as f:
        html_content = f.read()
    assert "VAK-2026-084" in html_content
    assert "Test uzman notu" in html_content
    assert "SHA-256" in html_content

    pdf_path = str(tmp_path / "forensic_report.pdf")
    rsvc.export_pdf(pdf_path)
    assert (tmp_path / "forensic_report.pdf").stat().st_size > 1500
