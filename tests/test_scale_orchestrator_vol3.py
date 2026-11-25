"""Automated tests for Performance Pagination, Orchestrator/PluginRegistry, CASE/UCO & BodyFile export, and Volatility 3 bridge."""

import json
import time

from src.core.orchestrator import AnalysisOrchestrator, JobStatus
from src.registry_engine.windows_artifacts import create_synthetic_windows_artifacts
from src.email_network_engine import create_synthetic_eml_file, create_synthetic_pcap_file
from src.memory_engine.memory_service import MemoryForensicsEngine
from src.ui.components.data_table import ForensicDataTable, ForensicTableModel


def test_paginated_datatable_handles_100k_rows_without_freezing(qapp):
    """Verify ForensicDataTable pagination + ForensicTableModel handle 100,000 records swiftly."""
    big_rows = [
        {"Durum": "Doğrulandı" if i % 2 == 0 else "İnceleniyor", "Dosya": f"file_{i}.dat", "Boyut": str(i * 10)}
        for i in range(100000)
    ]
    t0 = time.perf_counter()
    model = ForensicTableModel(["Durum", "Dosya", "Boyut"], big_rows)
    assert model.rowCount() == 100000

    tbl = ForensicDataTable(["Durum", "Dosya", "Boyut"], page_size=200)
    tbl.build_pagination_bar()
    tbl.set_records(big_rows)
    elapsed = time.perf_counter() - t0

    assert elapsed < 3.0
    assert tbl.total_record_count() == 100000
    assert tbl.page_count() == 500
    assert tbl.rowCount() == 200
    tbl.next_page()
    assert tbl.current_page() == 1


def test_orchestrator_ingest_pipeline_and_interchange_exports(tmp_path):
    """Verify PluginRegistry auto-matching, AnalysisOrchestrator execution/persistence, CASE/UCO JSON-LD & BodyFile."""
    db_file = str(tmp_path / "orch.db")
    orch = AnalysisOrchestrator(db_path=db_file)
    assert len(orch.registry.list_plugins()) >= 6

    arts = create_synthetic_windows_artifacts(str(tmp_path / "win"))
    eml_p = str(tmp_path / "mail.eml")
    create_synthetic_eml_file(eml_p)
    pcap_p = str(tmp_path / "net.pcap")
    create_synthetic_pcap_file(pcap_p)

    j1 = orch.submit_job(case_id=1, source_path=arts["pf"])
    j2 = orch.submit_job(case_id=1, source_path=eml_p)
    j3 = orch.submit_job(case_id=1, source_path=pcap_p)
    assert j1.status == JobStatus.QUEUED

    done = orch.run_pending_jobs()
    assert all(j.status == JobStatus.COMPLETED for j in done)
    assert sum(j.findings_count for j in done) >= 3

    uco_path = str(tmp_path / "case_uco.json")
    orch.export_case_uco_jsonld(case_id=1, output_path=uco_path)
    bundle = json.loads(open(uco_path, "r", encoding="utf-8").read())
    assert "@graph" in bundle and len(bundle["@graph"]) >= 4

    body_p = str(tmp_path / "tl.body")
    jsonl_p = str(tmp_path / "tl.jsonl")
    from src.timeline_engine.timeline_service import TimelineService
    events = TimelineService(db_path=db_file).collect_case_timeline(case_id=1)
    orch.export_timeline_bodyfile(events, body_p)
    orch.export_timeline_jsonl(events, jsonl_p)
    assert (tmp_path / "tl.body").read_text(encoding="utf-8").strip()
    assert (tmp_path / "tl.jsonl").read_text(encoding="utf-8").strip()


def test_memory_truncation_warning_and_vol3_bridge(tmp_path):
    """Verify memory dump engine emits explicit truncation warning when image > max_scan_mb and handles vol3 bridge cleanly."""
    big_dmp = tmp_path / "big_raw.dmp"
    # 2 MB raw file inspected with 1 MB limit triggers explicit truncation warning
    big_dmp.write_bytes(b"PAGEDU64" + b"\x00" * (2 * 1024 * 1024))
    res = MemoryForensicsEngine().inspect_memory_dump(str(big_dmp), max_scan_mb=1)
    assert any("tarama sınırı" in w for w in res["warnings"])

    vol_res = MemoryForensicsEngine.run_volatility3_plugin(str(big_dmp), plugin="windows.pslist")
    assert vol_res["plugin"] == "windows.pslist"
    assert "rows" in vol_res
