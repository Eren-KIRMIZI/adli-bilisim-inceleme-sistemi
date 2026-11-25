"""End-to-End Real Forensic Investigation & Suspect-PC Case Runner (VAK-2026-084).

Executes BOTH:
  1. Live read-only Windows 11 host verification (PowerShell Get-FileHash parity,
     winreg Run/Services/UserAssist/ShimCache/USBSTOR, real .lnk + OLE2 Jump Lists,
     Win32 Toolhelp32 processes).
  2. Complete 11-engine suspect-PC forensic investigation across realistic binary &
     SQLite artifacts (examples/suspect_pc_case), producing concrete court-ready
     outputs in outputs/vak_2026_084/:
       - investigation_findings.json
       - adli_rapor_vak_2026_084.html
       - adli_rapor_vak_2026_084.pdf
       - vak_2026_084_case_uco.json
       - vak_2026_084_timeline.jsonl
       - vak_2026_084_bodyfile.txt
"""

import json
import os
import subprocess
import sys
from datetime import datetime
from typing import Any, Dict

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.core.case_workspace import prepare_suspect_case_workspace
from src.core.orchestrator import AnalysisOrchestrator
from src.database.models import init_db, ForensicArtifact, Case
from src.database.seed import seed_database_if_empty
from src.integrity_engine.integrity_service import IntegrityService
from src.ntfs_engine.ntfs_service import DiskForensicsEngine
from src.registry_engine.hive_parser import RegistryHiveParser
from src.registry_engine.windows_artifacts import WindowsArtifactParsers
from src.eventlog_engine.evtx_service import EventLogService
from src.usb_engine.usb_service import UsbService
from src.browser_engine.browser_service import BrowserForensicsEngine
from src.memory_engine.memory_service import MemoryForensicsEngine
from src.file_engine.file_service import FileAnalysisService
from src.file_engine.threat_scanner import YaraStyleScanner, HashSetService
from src.email_network_engine import EmailForensicsService, NetworkForensicsService
from src.timeline_engine.timeline_service import TimelineService
from src.correlation_engine.correlation_service import CorrelationService
from src.report_engine.report_service import ReportService
from src.acquisition_engine.acquisition_service import AcquisitionService
from src.core.auth_service import AuthService
from src.core.privilege_service import PrivilegeService
from src.core.signing_service import SigningService


def _ps_sha256(path: str) -> str:
    cmd = [
        "powershell",
        "-NoProfile",
        "-Command",
        f"(Get-FileHash -Algorithm SHA256 -LiteralPath '{path}').Hash.ToLower()",
    ]
    res = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
    return res.stdout.strip().lower() if res.returncode == 0 else ""


def run_investigation() -> Dict[str, Any]:
    out_dir = os.path.abspath("outputs/vak_2026_084")
    os.makedirs(out_dir, exist_ok=True)
    db_path = os.path.join(out_dir, "vak_2026_084_run.db")
    if os.path.exists(db_path):
        os.remove(db_path)

    seed_database_if_empty(db_path)
    ws = prepare_suspect_case_workspace("examples/suspect_pc_case")

    report: Dict[str, Any] = {
        "generated_utc": datetime.utcnow().isoformat() + "Z",
        "case_number": "VAK-2026-084",
        "part_a_host_windows_verification": {},
        "part_b_suspect_case_findings": {},
        "exported_deliverables": [],
    }

    # --- PART A: Live Windows Host Triage & PowerShell Hash Cross-Verification ---
    ps_hash = _ps_sha256(ws["disk_image"])
    our_hashes = IntegrityService.compute_dual_hashes(ws["disk_image"])
    triage = RegistryHiveParser().read_live_windows_triage() if os.name == "nt" else {"supported": False}
    usb_live = UsbService(db_path=db_path).scan_live_system() if os.name == "nt" else []
    mem_engine = MemoryForensicsEngine()
    live_procs = mem_engine.capture_live_windows_processes()

    report["part_a_host_windows_verification"] = {
        "disk_image_sha256_integrity_service": our_hashes["sha256"].lower(),
        "disk_image_sha256_powershell_get_filehash": ps_hash,
        "hash_cross_verification_matched": (our_hashes["sha256"].lower() == ps_hash) if ps_hash else None,
        "live_registry_supported": bool(triage.get("supported")),
        "live_registry_counts": {k: len(v) for k, v in triage.get("categories", {}).items()},
        "live_usbstor_devices_detected": [
            {"name": d.device_name, "serial": d.serial_number}
            for d in usb_live
        ],
        "live_windows_processes_count": len(live_procs.get("processes", [])) if live_procs.get("supported") else 0,
    }

    # --- PART B: Full 11-Engine Analysis of Suspect PC Evidence Bundle ---
    ntfs_res = DiskForensicsEngine().inspect_image(ws["disk_image"])
    carved = DiskForensicsEngine().carve_signatures(ws["disk_image"])

    hive_parser = RegistryHiveParser()
    hive_parsed = hive_parser.parse_hive_file(ws["registry_hive"])
    hive_arts = hive_parser.extract_hive_forensics_artifacts(hive_parsed)

    evtx_res = EventLogService().parse_evtx_file(ws["evtx_log"])

    win_arts_summary: Dict[str, Any] = {}
    for key, p in ws["win_artifacts"].items():
        if p.endswith(".lnk"):
            lnk = WindowsArtifactParsers.parse_lnk(p)
            win_arts_summary[key] = {"target": lnk["target_path"], "size": lnk["target_file_size"]}
        elif p.endswith(".pf"):
            pf = WindowsArtifactParsers.parse_prefetch(p)
            win_arts_summary[key] = {"exe": pf["executable"], "run_count": pf["run_count"], "hash": pf["prefetch_hash"]}
        elif p.endswith(".automaticDestinations-ms"):
            jl = WindowsArtifactParsers.parse_jump_list(p)
            win_arts_summary[key] = {"streams_extracted": len(jl), "sample_targets": [x["target_path"] for x in jl[:3]]}
        elif os.path.basename(p).startswith("$I"):
            rb = WindowsArtifactParsers.parse_recycle_bin_i(p)
            win_arts_summary[key] = {"original_path": rb["original_path"], "deleted_size": rb["original_size"]}

    pcap_res = NetworkForensicsService.parse_pcap(ws["pcap_file"])
    eml_res = EmailForensicsService.parse_eml(ws["eml_file"])

    b_eng = BrowserForensicsEngine()
    hist_res = b_eng.parse_sqlite_artifact(ws["browser_history"], browser_hint="Google Chrome")
    bmark_res = b_eng.parse_chromium_bookmarks_json(ws["browser_bookmarks"], browser_name="Google Chrome")

    mem_res = mem_engine.inspect_memory_dump(ws["memory_dump"])

    payload_meta = FileAnalysisService.analyze(ws["disguised_payload"])
    yara_hits = YaraStyleScanner().scan_file(ws["disguised_payload"])
    dup_scan = FileAnalysisService.scan_directory_duplicates(ws["case_dir"])

    # Orchestrator ingest + exports
    Session = init_db(db_path)
    with Session() as s:
        case = s.query(Case).filter(Case.case_number == "VAK-2026-084").first()
        cid = case.id if case else 1

    orch = AnalysisOrchestrator(db_path=db_path)
    for target_file in (
        ws["disk_image"],
        ws["registry_hive"],
        ws["evtx_log"],
        ws["browser_history"],
        ws["memory_dump"],
        ws["disguised_payload"],
        ws["eml_file"],
        ws["pcap_file"],
    ):
        orch.submit_job(case_id=cid, source_path=target_file)
    jobs = orch.run_pending_jobs()

    # Record multi-module findings into ForensicArtifact for Timeline, Relations & Reports
    with Session() as s:
        findings_to_persist = [
            ForensicArtifact(
                case_id=cid,
                artifact_type="Extension Spoofing + YARA",
                source_path=ws["disguised_payload"],
                source_location="Dosya & YARA Analizi",
                extracted_data=json.dumps({
                    "title": f"Sahte Uzantı & YARA: {payload_meta['name']}",
                    "real_signature": payload_meta["signature_type"],
                    "sha256": payload_meta["sha256"],
                    "rules": [h["rule"] for h in yara_hits],
                }, ensure_ascii=False),
                original_timestamp="2026-03-15T09:24:12Z",
                normalized_timestamp=datetime(2026, 3, 15, 9, 24, 12),
                parser_name="FileAnalysisService+YaraStyleScanner",
                parser_version="1.0.0",
                confidence=100,
                warnings="Kritik: .jpg uzantısı altında Windows MZ/PE ikilisi ve kodlu PowerShell yükü tespit edildi.",
            ),
            ForensicArtifact(
                case_id=cid,
                artifact_type="Memory IOC & EPROCESS",
                source_path=ws["memory_dump"],
                source_location="RAM Bellek Analizi",
                extracted_data=json.dumps({
                    "title": "Bellekte C2 IP & PE Enjeksiyon İzi",
                    "pe_modules": len(mem_res["pe_modules"]),
                    "eprocess_candidates": len(mem_res["eprocess_candidates"]),
                    "iocs": [i["value"] for i in mem_res["iocs"]],
                }, ensure_ascii=False),
                original_timestamp="2026-03-15T10:05:40Z",
                normalized_timestamp=datetime(2026, 3, 15, 10, 5, 40),
                parser_name="MemoryForensicsEngine",
                parser_version="1.0.0",
                confidence=90,
                warnings="Heuristik bellek taramasında PE modülü ve ağ IOC kalıntıları bulundu.",
            ),
            ForensicArtifact(
                case_id=cid,
                artifact_type="DNS/HTTP C2 + Phishing EML",
                source_path=ws["pcap_file"],
                source_location="Ağ & E-posta Analizi",
                extracted_data=json.dumps({
                    "title": f"Şüpheli Ağ İletişimi & E-posta ({eml_res['subject']})",
                    "from": eml_res["from"],
                    "dns": [d["domain"] for d in pcap_res["dns_queries"]],
                    "http_iocs": [h["ioc"] for h in pcap_res["http_iocs"]],
                }, ensure_ascii=False),
                original_timestamp="2026-03-15T10:12:05Z",
                normalized_timestamp=datetime(2026, 3, 15, 10, 12, 5),
                parser_name="EmailNetworkForensicsService",
                parser_version="1.0.0",
                confidence=95,
            ),
        ]
        s.add_all(findings_to_persist)
        s.commit()

    tl_svc = TimelineService(db_path=db_path)
    tl_svc.ingest_mft_records(ntfs_res.get("mft_records", []), source_label="suspect_usb_disk.dd::$MFT")
    tl_svc.ingest_evtx_events(evtx_res.get("events", []), source_label="Security.evtx")
    tl_svc.ingest_eml(eml_res)
    tl_events = tl_svc.collect_case_timeline(case_id=cid)
    corr_graph = CorrelationService(db_path=db_path).build_case_graph(include_hypotheses=True)

    # Export deliverables
    uco_path = os.path.join(out_dir, "vak_2026_084_case_uco.json")
    jsonl_path = os.path.join(out_dir, "vak_2026_084_timeline.jsonl")
    body_path = os.path.join(out_dir, "vak_2026_084_bodyfile.txt")
    html_path = os.path.join(out_dir, "adli_rapor_vak_2026_084.html")
    pdf_path = os.path.join(out_dir, "adli_rapor_vak_2026_084.pdf")
    json_path = os.path.join(out_dir, "investigation_findings.json")

    orch.export_case_uco_jsonld(cid, uco_path)
    AnalysisOrchestrator.export_timeline_jsonl(tl_events, jsonl_path)
    AnalysisOrchestrator.export_timeline_bodyfile(tl_events, body_path)

    expert_notes = (
        "VAK-2026-084 kapsamında incelenen şüpheli imajlarda USB flash bellek bağlantısının hemen ardından "
        "tatil_fatura_ek.jpg adı altında PE/MZ çalıştırılabilir zararlı yükü, Base64 kodlu PowerShell komutu ve rclone "
        "veri sızdırma aracı izi saptanmıştır. RAM dökümünde KDBG, EPROCESS adayları ve harici IP/URL IOC'leri tespit edilmiştir."
    )
    rep_svc = ReportService(db_path=db_path)
    rep_svc.export_html(html_path, case_id=cid, expert_notes=expert_notes)
    rep_svc.export_pdf(pdf_path, case_id=cid, expert_notes=expert_notes)

    # v2.0 Enterprise Layers: Field Acquisition, X.509 Report Signing, RBAC & Privilege Status
    acq_out = os.path.join(out_dir, "acquired_suspect_disk.dd")
    acq_manifest = AcquisitionService.acquire_raw_image(
        ws["disk_image"],
        acq_out,
        write_blocker_verified=True,
        write_blocker_model="Tableau T8u Forensic Bridge",
        operator="Adli Bilişim Uzmanı E. Kırmızı",
        case_number="VAK-2026-084",
    )
    cert_dir = os.path.join(out_dir, "certs")
    pdf_sig = SigningService.sign_file(pdf_path, "Adli Bilişim Uzmanı E. Kırmızı", "LeadInvestigator", cert_dir=cert_dir)
    html_sig = SigningService.sign_file(html_path, "Adli Bilişim Uzmanı E. Kırmızı", "LeadInvestigator", cert_dir=cert_dir)
    pdf_verify = SigningService.verify_signature(pdf_path, pdf_sig["signature_path"])

    auth_svc = AuthService(db_path=db_path)
    priv_status = PrivilegeService.get_status()

    mft_active = sum(1 for r in ntfs_res.get("mft_records", []) if not r.get("is_deleted"))
    mft_deleted = sum(1 for r in ntfs_res.get("mft_records", []) if r.get("is_deleted"))

    report["part_b_suspect_case_findings"] = {
        "disk_ntfs": {
            "format": ntfs_res.get("format"),
            "partitions": len(ntfs_res.get("partitions", [])),
            "mft_active_files": mft_active,
            "mft_deleted_files": mft_deleted,
            "carved_signatures": len(carved),
        },
        "windows_registry_and_evtx": {
            "hive_keys_parsed": hive_parsed.get("total_keys_parsed"),
            "hive_forensic_artifacts": len(hive_arts),
            "evtx_events_parsed": len(evtx_res.get("events", [])),
            "artifacts": win_arts_summary,
        },
        "browser_forensics": {
            "history_urls": len(hist_res.get("history", [])),
            "downloads": len(hist_res.get("downloads", [])),
            "searches": len(hist_res.get("searches", [])),
            "bookmarks": len(bmark_res),
        },
        "memory_forensics": {
            "format": mem_res.get("format"),
            "kdbg_offsets": mem_res.get("kdbg_offsets"),
            "eprocess_candidates": [e["image_name"] for e in mem_res.get("eprocess_candidates", [])],
            "pe_modules_count": len(mem_res.get("pe_modules", [])),
            "iocs": [i["value"] for i in mem_res.get("iocs", [])],
        },
        "file_yara_and_network": {
            "disguised_file": payload_meta["name"],
            "disguised_real_signature": payload_meta["signature_type"],
            "extension_mismatch": payload_meta["extension_mismatch"],
            "entropy": payload_meta["entropy"],
            "sha256": payload_meta["sha256"],
            "yara_hits": [h["rule"] for h in yara_hits],
            "duplicate_groups": dup_scan["duplicate_groups"],
            "pcap_dns_queries": [d["domain"] for d in pcap_res["dns_queries"]],
            "pcap_http_iocs": [h["ioc"] for h in pcap_res["http_iocs"]],
            "eml_subject": eml_res["subject"],
            "eml_attachments": [a["filename"] for a in eml_res["attachments"]],
        },
        "orchestrator_jobs_completed": sum(1 for j in jobs if j.status.name == "COMPLETED"),
        "super_timeline_events": len(tl_events),
        "correlation_graph": {"nodes": len(corr_graph["nodes"]), "edges": len(corr_graph["edges"])},
        "v2_field_acquisition": {
            "source": ws["disk_image"],
            "acquired_image": acq_out,
            "bytes_acquired": acq_manifest["bytes_acquired"],
            "post_verification_matched": acq_manifest["post_verification_matched"],
            "storage_targets_enumerated": len(AcquisitionService.list_storage_targets()),
        },
        "v2_x509_report_signing": {
            "algorithm": SigningService.ALGORITHM,
            "cert_fingerprint_sha256": pdf_sig["cert_fingerprint_sha256"],
            "pdf_verified_valid": pdf_verify["valid"],
            "pdf_sig_path": pdf_sig["signature_path"],
            "html_sig_path": html_sig["signature_path"],
        },
        "v2_rbac_and_privilege": {
            "rbac_users_count": len(auth_svc.list_users()),
            "is_admin": priv_status["is_admin"],
            "wevtutil_available": priv_status["wevtutil_available"],
        },
    }
    report["exported_deliverables"] = [
        json_path, html_path, html_sig["signature_path"], pdf_path, pdf_sig["signature_path"],
        uco_path, jsonl_path, body_path, acq_out, acq_manifest["manifest_path"]
    ]

    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return report


if __name__ == "__main__":
    summary = run_investigation()
    print(json.dumps(summary, indent=2, ensure_ascii=False))
