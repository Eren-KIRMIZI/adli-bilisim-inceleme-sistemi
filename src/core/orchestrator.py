"""Decoupled Plugin Registry, Background Analysis Job Orchestrator, and CASE/UCO + BodyFile Exporters."""

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
import json
import os
import time
from typing import Any, Callable, Dict, List, Optional
import uuid

from src.core.models import ForensicArtifactModel
from src.database.models import init_db, Case, Evidence, ForensicArtifact, append_audit_log
from src.database.seed import seed_database_if_empty


class JobStatus(str, Enum):
    QUEUED = "Queued"
    RUNNING = "Running"
    PAUSED = "Paused"
    COMPLETED = "Completed"
    FAILED = "Failed"
    CANCELLED = "Cancelled"


@dataclass
class ForensicPlugin:
    plugin_id: str
    name: str
    version: str
    extensions: tuple
    runner: Callable[[str, int, Optional[int]], List[ForensicArtifactModel]]


@dataclass
class AnalysisJob:
    job_id: str
    case_id: int
    evidence_id: Optional[int]
    plugin_id: str
    source_path: str
    status: JobStatus = JobStatus.QUEUED
    progress_pct: int = 0
    processed_bytes: int = 0
    findings_count: int = 0
    elapsed_sec: float = 0.0
    warnings: List[str] = field(default_factory=list)
    error: Optional[str] = None
    artifacts: List[ForensicArtifactModel] = field(default_factory=list)


class PluginRegistry:
    """Extensible registry decoupling forensic parsers from orchestrators & UI."""

    def __init__(self):
        self._plugins: Dict[str, ForensicPlugin] = {}
        self._register_defaults()

    def register(self, plugin: ForensicPlugin) -> None:
        self._plugins[plugin.plugin_id] = plugin

    def get(self, plugin_id: str) -> Optional[ForensicPlugin]:
        return self._plugins.get(plugin_id)

    def list_plugins(self) -> List[ForensicPlugin]:
        return list(self._plugins.values())

    def match_for_file(self, path: str) -> List[ForensicPlugin]:
        low = os.path.basename(path).lower()
        return [p for p in self._plugins.values() if any(low.endswith(ext) or ext in low for ext in p.extensions)]

    def _register_defaults(self) -> None:
        def _run_disk(path: str, case_id: int, evd_id: Optional[int]) -> List[ForensicArtifactModel]:
            from src.ntfs_engine.ntfs_service import DiskForensicsEngine
            res = DiskForensicsEngine().inspect_image(path)
            out: List[ForensicArtifactModel] = []
            for r in res.get("mft_records", [])[:500]:
                out.append(ForensicArtifactModel(
                    artifact_id=f"mft-{r['record_index']}-{uuid.uuid4().hex[:8]}",
                    case_id=case_id,
                    evidence_id=evd_id,
                    artifact_type="Disk/MFT",
                    source_file=path,
                    source_location=r.get("full_path", r.get("filename", "-")),
                    extracted_data={
                        "filename": r.get("filename"),
                        "size": r.get("size"),
                        "is_deleted": r.get("is_deleted"),
                        "timestomping_suspect": r.get("timestomping_suspect", False),
                        "ads_streams": r.get("ads_streams", []),
                    },
                    normalized_timestamp=r.get("created"),
                    parser_name="DiskForensicsEngine",
                    parser_version="2.0",
                    confidence=95 if r.get("fixup_ok", True) else 65,
                    warnings=res.get("warnings", [])[:3],
                ))
            return out

        def _run_evtx(path: str, case_id: int, evd_id: Optional[int]) -> List[ForensicArtifactModel]:
            from src.eventlog_engine.evtx_service import EventLogService
            res = EventLogService().parse_evtx_file(path, max_records=500)
            return [
                ForensicArtifactModel(
                    artifact_id=f"evtx-{ev.get('record_id', idx)}-{uuid.uuid4().hex[:6]}",
                    case_id=case_id,
                    evidence_id=evd_id,
                    artifact_type="EventLog/EVTX",
                    source_file=path,
                    source_location=f"Record #{ev.get('record_id')} (EventID {ev.get('event_id')})",
                    extracted_data={"event_id": ev.get("event_id"), "description": ev.get("description"), "details": ev.get("details")},
                    normalized_timestamp=ev.get("timestamp"),
                    parser_name="EventLogService",
                    parser_version="2.0",
                    confidence=95,
                    warnings=res.get("warnings", []),
                )
                for idx, ev in enumerate(res.get("records", []))
            ]

        def _run_prefetch(path: str, case_id: int, evd_id: Optional[int]) -> List[ForensicArtifactModel]:
            from src.registry_engine.windows_artifacts import WindowsArtifactParsers
            pf = WindowsArtifactParsers.parse_prefetch(path)
            return [ForensicArtifactModel(
                artifact_id=f"pf-{uuid.uuid4().hex[:8]}",
                case_id=case_id,
                evidence_id=evd_id,
                artifact_type="Prefetch",
                source_file=path,
                source_location=pf.get("executable", "-"),
                extracted_data={"run_count": pf.get("run_count"), "last_run_times": len(pf.get("last_run_times", []))},
                normalized_timestamp=pf.get("last_run"),
                parser_name="WindowsArtifactParsers",
                parser_version="2.0",
                confidence=95 if not pf.get("warnings") else 60,
                warnings=pf.get("warnings", []),
            )]

        def _run_eml(path: str, case_id: int, evd_id: Optional[int]) -> List[ForensicArtifactModel]:
            from src.email_network_engine import EmailForensicsService
            eml = EmailForensicsService.parse_eml(path)
            return [ForensicArtifactModel(
                artifact_id=f"eml-{uuid.uuid4().hex[:8]}",
                case_id=case_id,
                evidence_id=evd_id,
                artifact_type="Email/EML",
                source_file=path,
                source_location=eml.get("subject", "-"),
                extracted_data={"from": eml.get("from"), "to": eml.get("to"), "urls": eml.get("urls", [])},
                normalized_timestamp=eml.get("date_utc"),
                parser_name="EmailForensicsService",
                parser_version="1.0",
                confidence=95,
            )]

        def _run_pcap(path: str, case_id: int, evd_id: Optional[int]) -> List[ForensicArtifactModel]:
            from src.email_network_engine import NetworkForensicsService
            pcap = NetworkForensicsService.parse_pcap(path)
            return [ForensicArtifactModel(
                artifact_id=f"pcap-{uuid.uuid4().hex[:8]}",
                case_id=case_id,
                evidence_id=evd_id,
                artifact_type="Network/PCAP",
                source_file=path,
                source_location=f"{pcap.get('packet_count', 0)} paket",
                extracted_data={"dns_queries": len(pcap.get("dns_queries", [])), "http_iocs": len(pcap.get("http_iocs", []))},
                parser_name="NetworkForensicsService",
                parser_version="1.0",
                confidence=90,
            )]

        def _run_file_threat(path: str, case_id: int, evd_id: Optional[int]) -> List[ForensicArtifactModel]:
            from src.file_engine.file_service import FileAnalysisService
            from src.file_engine.threat_scanner import YaraStyleScanner
            info = FileAnalysisService.analyze(path)
            hits = YaraStyleScanner().scan_file(path)
            return [ForensicArtifactModel(
                artifact_id=f"file-{uuid.uuid4().hex[:8]}",
                case_id=case_id,
                evidence_id=evd_id,
                artifact_type="YARA/File" if hits else "File/Inspection",
                source_file=path,
                source_location=info["name"],
                extracted_data={"sha256": info["sha256"], "signature": info["signature_type"], "yara_hits": [h["rule"] for h in hits]},
                parser_name="FileAnalysisService+YaraStyleScanner",
                parser_version="2.0",
                confidence=100,
            )]

        self.register(ForensicPlugin("ntfs_disk", "NTFS/E01 Disk İnceleme", "2.0", (".dd", ".raw", ".img", ".e01", "$mft"), _run_disk))
        self.register(ForensicPlugin("evtx_logs", "EVTX BinXml Ayrıştırıcı", "2.0", (".evtx",), _run_evtx))
        self.register(ForensicPlugin("prefetch", "Windows Prefetch (.pf)", "2.0", (".pf",), _run_prefetch))
        self.register(ForensicPlugin("eml_email", "RFC 5322 E-posta (.eml)", "1.0", (".eml",), _run_eml))
        self.register(ForensicPlugin("pcap_network", "libpcap Ağ Analizi (.pcap)", "1.0", (".pcap",), _run_pcap))
        self.register(ForensicPlugin("file_threat", "Dosya & YARA-Stili Tarama", "2.0", (".ps1", ".exe", ".dll", ".txt", ".jpg", ".pdf", ".zip"), _run_file_threat))


class AnalysisOrchestrator:
    """Queues, runs, tracks, and persists multi-engine ingest jobs into SQLite + exports CASE/UCO & BodyFile."""

    def __init__(self, db_path: str = "data/forensics.db", registry: Optional[PluginRegistry] = None):
        self.db_path = db_path
        self.Session = init_db(db_path)
        seed_database_if_empty(db_path)
        self.registry = registry or PluginRegistry()
        self.jobs: Dict[str, AnalysisJob] = {}
        self._cancel_requested = False

    def submit_job(self, case_id: int, source_path: str, plugin_id: Optional[str] = None, evidence_id: Optional[int] = None) -> AnalysisJob:
        pid = plugin_id
        if not pid:
            matches = self.registry.match_for_file(source_path)
            pid = matches[0].plugin_id if matches else "file_threat"
        job = AnalysisJob(
            job_id=uuid.uuid4().hex[:10],
            case_id=case_id,
            evidence_id=evidence_id,
            plugin_id=pid,
            source_path=source_path,
        )
        self.jobs[job.job_id] = job
        return job

    def cancel_all(self) -> None:
        self._cancel_requested = True

    def run_pending_jobs(self, progress_callback: Optional[Callable[[int, str], None]] = None) -> List[AnalysisJob]:
        self._cancel_requested = False
        pending = [j for j in self.jobs.values() if j.status == JobStatus.QUEUED]
        total = max(1, len(pending))
        completed: List[AnalysisJob] = []

        for idx, job in enumerate(pending, 1):
            if self._cancel_requested:
                job.status = JobStatus.CANCELLED
                completed.append(job)
                continue

            plugin = self.registry.get(job.plugin_id)
            if not plugin:
                job.status = JobStatus.FAILED
                job.error = f"Kayıtlı eklenti bulunamadı: {job.plugin_id}"
                completed.append(job)
                continue

            job.status = JobStatus.RUNNING
            t0 = time.perf_counter()
            try:
                job.processed_bytes = os.path.getsize(job.source_path) if os.path.isfile(job.source_path) else 0
                arts = plugin.runner(job.source_path, job.case_id, job.evidence_id)
                job.artifacts = arts
                job.findings_count = len(arts)
                for a in arts:
                    job.warnings.extend(a.warnings)
                job.elapsed_sec = round(time.perf_counter() - t0, 4)
                job.progress_pct = 100
                job.status = JobStatus.COMPLETED

                # Persist normalized ForensicArtifact rows & audit chain in one transaction
                with self.Session() as s:
                    for a in arts:
                        s.add(ForensicArtifact(
                            case_id=a.case_id,
                            evidence_id=a.evidence_id,
                            artifact_type=a.artifact_type,
                            source_path=a.source_file,
                            source_location=a.source_location,
                            extracted_data=json.dumps(a.extracted_data, ensure_ascii=False, default=str),
                            original_timestamp=a.original_timestamp,
                            normalized_timestamp=a.normalized_timestamp,
                            parser_name=a.parser_name,
                            parser_version=a.parser_version,
                            confidence=a.confidence,
                            warnings="\n".join(a.warnings) if a.warnings else None,
                        ))
                    append_audit_log(
                        s,
                        job.case_id,
                        "AnalysisOrchestrator",
                        f"Ingest Tamamlandı ({plugin.plugin_id})",
                        f"{os.path.basename(job.source_path)} -> {job.findings_count} artefakt ({job.elapsed_sec}s)",
                    )
                    s.commit()
            except Exception as exc:
                job.elapsed_sec = round(time.perf_counter() - t0, 4)
                job.status = JobStatus.FAILED
                job.error = str(exc)

            if progress_callback:
                progress_callback(int((idx * 100) / total), f"{plugin.name}: {job.status.value}")
            completed.append(job)
        return completed

    def export_case_uco_jsonld(self, case_id: int, output_path: str) -> str:
        """Export case, evidences, and extracted ForensicArtifacts as a CASE / UCO JSON-LD bundle."""
        with self.Session() as s:
            c = s.query(Case).filter(Case.id == case_id).first()
            if not c:
                raise ValueError(f"Vaka bulunamadı: ID={case_id}")
            evds = s.query(Evidence).filter(Evidence.case_id == case_id).all()
            arts = s.query(ForensicArtifact).filter(ForensicArtifact.case_id == case_id).all()

            graph: List[Dict[str, Any]] = [
                {
                    "@id": f"urn:case:{c.case_number}",
                    "@type": "case-investigation:Investigation",
                    "name": c.title,
                    "startTime": c.opened_at.isoformat() + "Z" if c.opened_at else None,
                    "investigationStatus": c.status,
                }
            ]
            for e in evds:
                graph.append({
                    "@id": f"urn:evidence:{e.evidence_number}",
                    "@type": "uco-observable:ObservableObject",
                    "description": f"{e.device_type} {e.brand} {e.model}".strip(),
                    "serialNumber": e.serial,
                    "sha256": e.sha256_hash,
                    "writeBlockerUsed": bool(e.write_blocker_used),
                })
            for a in arts:
                graph.append({
                    "@id": f"urn:artifact:{a.id}",
                    "@type": "uco-observable:ForensicArtifact",
                    "artifactType": a.artifact_type,
                    "sourcePath": a.source_path,
                    "sourceLocation": a.source_location,
                    "parser": f"{a.parser_name}/{a.parser_version}",
                    "confidence": a.confidence,
                    "normalizedTimestamp": a.normalized_timestamp.isoformat() + "Z" if a.normalized_timestamp else None,
                })

        bundle = {
            "@context": {
                "case-investigation": "https://ontology.caseontology.org/case/investigation/",
                "uco-observable": "https://ontology.unifiedcyberontology.org/uco/observable/",
            },
            "@graph": graph,
        }
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2, ensure_ascii=False)
        return output_path

    @staticmethod
    def export_timeline_bodyfile(events: List[Dict[str, Any]], output_path: str) -> str:
        """Export timeline events in Sleuth Kit 3.x Body File format (MD5|name|inode|mode|UID|GID|size|atime|mtime|ctime|crtime)."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            for idx, ev in enumerate(events, 1):
                dt = ev.get("timestamp_utc")
                epoch = int(dt.timestamp()) if isinstance(dt, datetime) else 0
                name = str(ev.get("details", ev.get("event_type", "-"))).replace("|", "/")
                f.write(f"0|{name}|{idx}|----------|0|0|0|{epoch}|{epoch}|{epoch}|{epoch}\n")
        return output_path

    @staticmethod
    def export_timeline_jsonl(events: List[Dict[str, Any]], output_path: str) -> str:
        """Export standardized UTC timeline events as Timesketch-compatible JSONL."""
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            for ev in events:
                row = dict(ev)
                if isinstance(row.get("timestamp_utc"), datetime):
                    row["timestamp_utc"] = row["timestamp_utc"].isoformat() + "Z"
                f.write(json.dumps(row, ensure_ascii=False, default=str) + "\n")
        return output_path
