"""Read-only Real-World Windows 11 DFIR Validation & Cross-Verification Benchmark.

Runs strictly in read-only mode (copying locked files to an isolated temporary directory if needed),
cross-verifies cryptographic hashes against PowerShell Get-FileHash, exercises genuine Windows 11
Registry/Prefetch/LNK/JumpList/Browser/EVTX/Hosts/Processes artifacts, and records honest pass/fail counts.
"""

from datetime import datetime
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from src.integrity_engine.integrity_service import IntegrityService
from src.file_engine.file_service import FileAnalysisService
from src.registry_engine.hive_parser import RegistryHiveParser
from src.registry_engine.windows_artifacts import WindowsArtifactParsers
from src.eventlog_engine.evtx_service import EventLogService
from src.browser_engine.browser_service import BrowserForensicsEngine
from src.memory_engine.memory_service import MemoryForensicsEngine
from src.usb_engine.usb_service import UsbService
from src.email_network_engine import NetworkForensicsService


def run_validation() -> dict:
    report = {
        "timestamp_utc": datetime.utcnow().isoformat() + "Z",
        "os": os.name,
        "python": sys.version.split()[0],
        "checks": {},
    }

    with tempfile.TemporaryDirectory(prefix="dfir_real_val_") as tmp_dir:
        # 1. Cross-check IntegrityService SHA-256 against Windows PowerShell Get-FileHash on main.py
        target_f = os.path.abspath("main.py")
        our_hash = IntegrityService.compute_dual_hashes(target_f)["sha256"].lower()
        ps = subprocess.run(
            ["powershell", "-NoProfile", "-Command", f"(Get-FileHash -Algorithm SHA256 '{target_f}').Hash"],
            capture_output=True, text=True, timeout=10, check=False
        )
        ps_hash = ps.stdout.strip().lower()
        file_info = FileAnalysisService.analyze(target_f)
        report["checks"]["hash_cross_verification"] = {
            "our_sha256": our_hash,
            "powershell_get_filehash": ps_hash,
            "file_service_matches": file_info["sha256"].lower() == our_hash,
            "matched": bool(ps_hash and our_hash == ps_hash),
        }

        # 2. Live Windows 11 Registry Triage (Run/Services/Profiles/TypedPaths/UserAssist/ShimCache)
        triage = RegistryHiveParser().read_live_windows_triage()
        report["checks"]["live_registry_triage"] = {
            "supported": triage.get("supported", False),
            "counts": {k: len(v) for k, v in triage.get("categories", {}).items()},
        }

        # 3. Live USBSTOR Registry Scan
        usb_db = os.path.join(tmp_dir, "val_usb.db")
        usb_recs = UsbService(db_path=usb_db).scan_live_system()
        report["checks"]["live_usbstor"] = {
            "count": len(usb_recs),
            "sample_devices": [
                {"name": u.device_name, "serial": u.serial_number, "drive": u.drive_letter, "ts_honest_none": u.first_connected is None}
                for u in usb_recs[:5]
            ],
        }

        # 4. Real Windows 11 Prefetch (.pf - MAM compressed Win11)
        pf_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch")
        pf_files = sorted(glob.glob(os.path.join(pf_dir, "*.pf")))[:15] if os.path.isdir(pf_dir) else []
        pf_ok, pf_fail, pf_mam_warn = 0, 0, 0
        pf_samples = []
        for pf in pf_files:
            try:
                cp = os.path.join(tmp_dir, os.path.basename(pf))
                shutil.copy2(pf, cp)
                res = WindowsArtifactParsers.parse_prefetch(cp)
                if res.get("warnings"):
                    pf_mam_warn += 1
                else:
                    pf_ok += 1
                    if len(pf_samples) < 3:
                        pf_samples.append({
                            "file": os.path.basename(pf),
                            "exe": res.get("executable"),
                            "run_count": res.get("run_count"),
                            "timestamps_extracted": len(res.get("last_run_times", [])),
                            "loaded_files": len(res.get("loaded_files", [])),
                        })
            except Exception:
                pf_fail += 1
        report["checks"]["real_prefetch"] = {
            "dir_accessible": os.path.isdir(pf_dir),
            "tested": len(pf_files),
            "parsed_ok": pf_ok,
            "mam_warnings": pf_mam_warn,
            "errors": pf_fail,
            "samples": pf_samples,
        }

        # 5. Real Windows 11 LNK & AutomaticDestinations Jump Lists
        recent_dir = os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Recent")
        lnk_files = sorted(glob.glob(os.path.join(recent_dir, "*.lnk")))[:15] if os.path.isdir(recent_dir) else []
        lnk_ok, lnk_err = 0, 0
        for lf in lnk_files:
            try:
                WindowsArtifactParsers.parse_lnk(lf)
                lnk_ok += 1
            except Exception:
                lnk_err += 1

        auto_dir = os.path.join(recent_dir, "AutomaticDestinations")
        jl_files = sorted(glob.glob(os.path.join(auto_dir, "*.automaticDestinations-ms")))[:10] if os.path.isdir(auto_dir) else []
        jl_ok, jl_entries_total, jl_err = 0, 0, []
        for jf in jl_files:
            try:
                ents = WindowsArtifactParsers.parse_jump_list(jf)
                jl_ok += 1
                jl_entries_total += len(ents)
            except Exception as exc:
                jl_err.append(f"{os.path.basename(jf)}: {exc}")

        report["checks"]["real_lnk_and_jumplist"] = {
            "lnk_tested": len(lnk_files),
            "lnk_ok": lnk_ok,
            "lnk_errors": lnk_err,
            "jumplist_tested": len(jl_files),
            "jumplist_ok": jl_ok,
            "jumplist_streams_extracted": jl_entries_total,
            "jumplist_errors": jl_err[:5],
        }

        # 6. Real Windows 11 Event Logs (.evtx) read-only copy test
        evtx_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "winevt", "Logs")
        evtx_res = {}
        for name in ("System.evtx", "Application.evtx"):
            src_e = os.path.join(evtx_dir, name)
            if os.path.isfile(src_e):
                try:
                    dst_e = os.path.join(tmp_dir, name)
                    shutil.copy2(src_e, dst_e)
                    parsed_ev = EventLogService().parse_evtx_file(dst_e, max_records=25)
                    evtx_res[name] = {
                        "accessible": True,
                        "records_parsed": len(parsed_ev.get("records", [])),
                        "sample_event_ids": [r.get("event_id") for r in parsed_ev.get("records", [])[:5]],
                        "warnings": parsed_ev.get("warnings", [])[:2],
                    }
                except Exception as exc:
                    evtx_res[name] = {"accessible": False, "error": str(exc)}
        report["checks"]["real_evtx"] = evtx_res

        # 7. Real Browser Profiles (Chrome / Edge / Firefox)
        br_eng = BrowserForensicsEngine()
        profiles = br_eng.discover_local_profiles()
        br_results = []
        for prof in profiles[:4]:
            hist_path = prof.get("history", "")
            if not hist_path or not os.path.isfile(hist_path):
                continue
            try:
                parsed_b = br_eng.parse_sqlite_artifact(
                    hist_path, browser_hint=prof["browser"], profile_name=prof["profile"], max_rows=500
                )
                bmarks_cnt = 0
                if prof.get("bookmarks") and prof["bookmarks"].endswith("Bookmarks") and os.path.isfile(prof["bookmarks"]):
                    bmarks_cnt = len(br_eng.parse_chromium_bookmarks_json(prof["bookmarks"], prof["browser"], prof["profile"]))
                br_results.append({
                    "browser": prof["browser"],
                    "profile": prof["profile"],
                    "history": len(parsed_b.get("history", [])),
                    "downloads": len(parsed_b.get("downloads", [])),
                    "searches": len(parsed_b.get("searches", [])),
                    "bookmarks": bmarks_cnt,
                    "warnings": parsed_b.get("warnings", []),
                })
            except Exception as exc:
                br_results.append({"browser": prof["browser"], "profile": prof["profile"], "error": str(exc)})
        report["checks"]["real_browsers"] = {
            "profiles_discovered": len(profiles),
            "parsed_samples": br_results,
        }

        # 8. Live Toolhelp32 Processes & Hosts / Network Sockets
        mem_live = MemoryForensicsEngine().capture_live_windows_processes()
        hosts = NetworkForensicsService.read_hosts_file()
        conns = NetworkForensicsService.capture_live_connections(max_rows=30)
        report["checks"]["live_memory_and_network"] = {
            "live_processes_supported": mem_live.get("supported"),
            "live_processes_count": len(mem_live.get("processes", [])),
            "hosts_entries": len(hosts),
            "netstat_connections_sampled": len(conns),
        }

    return report


if __name__ == "__main__":
    print(json.dumps(run_validation(), indent=2, ensure_ascii=False))
