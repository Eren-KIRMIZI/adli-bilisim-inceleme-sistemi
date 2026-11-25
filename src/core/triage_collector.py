"""KAPE-Style Read-Only Live Triage Collector with SHA-256 / SHA-512 Manifest."""

import hashlib
import json
import os
import shutil
from datetime import datetime
from typing import Any, Dict, List, Optional


class TriageCollector:
    """Collects forensic artifact working copies with cryptographic manifest verification."""

    DEFAULT_TARGETS = [
        ("Prefetch", os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch"), (".pf",)),
        ("EventLogs", os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "winevt", "Logs"), (".evtx",)),
        ("RecentLNK", os.path.join(os.environ.get("APPDATA", ""), "Microsoft", "Windows", "Recent"), (".lnk", ".automaticdestinations-ms")),
        ("ChromeHistory", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data", "Default"), ("History", "Bookmarks")),
        ("EdgeHistory", os.path.join(os.environ.get("LOCALAPPDATA", ""), "Microsoft", "Edge", "User Data", "Default"), ("History", "Bookmarks")),
    ]

    @staticmethod
    def collect_from_directory(
        source_dir: str,
        output_dir: str,
        extensions: Optional[tuple] = None,
        max_files: int = 200,
    ) -> Dict[str, Any]:
        """Collect read-only working copies from a directory and produce a SHA-256 manifest."""
        if not os.path.isdir(source_dir):
            raise NotADirectoryError(source_dir)
        os.makedirs(output_dir, exist_ok=True)

        collected: List[Dict[str, Any]] = []
        skipped: List[Dict[str, str]] = []

        for root, _, files in os.walk(source_dir):
            for fname in files:
                if len(collected) >= max_files:
                    break
                if extensions and not (fname.lower().endswith(extensions) or fname in extensions):
                    continue
                src_path = os.path.join(root, fname)
                rel = os.path.relpath(src_path, source_dir)
                dst_path = os.path.join(output_dir, rel)
                os.makedirs(os.path.dirname(dst_path), exist_ok=True)
                try:
                    shutil.copy2(src_path, dst_path)
                    h256 = hashlib.sha256()
                    with open(dst_path, "rb") as f:
                        for chunk in iter(lambda: f.read(65536), b""):
                            h256.update(chunk)
                    collected.append({
                        "source": src_path,
                        "working_copy": dst_path,
                        "size": os.path.getsize(dst_path),
                        "sha256": h256.hexdigest(),
                    })
                except Exception as e:
                    skipped.append({"source": src_path, "reason": str(e)})

        manifest = {
            "collected_at_utc": datetime.utcnow().isoformat() + "Z",
            "source_root": source_dir,
            "collected_count": len(collected),
            "skipped_count": len(skipped),
            "files": collected,
            "skipped": skipped,
        }
        manifest_path = os.path.join(output_dir, "triage_manifest.json")
        with open(manifest_path, "w", encoding="utf-8") as mf:
            json.dump(manifest, mf, indent=2, ensure_ascii=False)
        manifest["manifest_path"] = manifest_path
        return manifest

    @classmethod
    def collect_live_system_triage(cls, output_root: str, max_per_target: int = 50) -> Dict[str, Any]:
        """Run KAPE-style collection across accessible Windows live artifact folders."""
        stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        session_dir = os.path.join(output_root, f"triage_{stamp}")
        os.makedirs(session_dir, exist_ok=True)
        summary: Dict[str, Any] = {"session_dir": session_dir, "targets": {}}

        for tname, tpath, exts in cls.DEFAULT_TARGETS:
            if tpath and os.path.isdir(tpath):
                res = cls.collect_from_directory(
                    tpath, os.path.join(session_dir, tname), extensions=exts, max_files=max_per_target
                )
                summary["targets"][tname] = {
                    "collected": res["collected_count"],
                    "skipped": res["skipped_count"],
                    "manifest": res["manifest_path"],
                }
        return summary

    @staticmethod
    def export_remote_triage_script(output_ps1_path: str) -> str:
        """Generate a Velociraptor/KAPE-style read-only PowerShell remote triage collector script."""
        script = r"""<#
.SYNOPSIS
  Adli Bilisim Inceleme Sistemi - Salt-Okunur Uzak Uc Nokta Triyaj Toplayicisi (v3.0)
  Velociraptor / KAPE tarzinda uzak Windows istemciden delil kopyasi ve SHA-256 manifesti uretir.
#>
param(
  [string]$OutDir = "$env:TEMP\DFIR_Triage_$(Get-Date -Format 'yyyyMMdd_HHmmss')"
)
$ErrorActionPreference = 'SilentlyContinue'
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$Manifest = @()

function Copy-ForensicItem([string]$Src, [string]$Sub) {
  if (Test-Path $Src) {
    $DstDir = Join-Path $OutDir $Sub
    New-Item -ItemType Directory -Force -Path $DstDir | Out-Null
    Copy-Item -Path $Src -Destination $DstDir -Force
    Get-ChildItem $DstDir -File | ForEach-Object {
      $h = (Get-FileHash -Algorithm SHA256 $_.FullName).Hash
      $script:Manifest += [PSCustomObject]@{ File = $_.Name; Category = $Sub; SHA256 = $h; Size = $_.Length }
    }
  }
}

Copy-ForensicItem "$env:SystemRoot\Prefetch\*.pf" "Prefetch"
Copy-ForensicItem "$env:SystemRoot\System32\winevt\Logs\Security.evtx" "EventLogs"
Copy-ForensicItem "$env:SystemRoot\System32\winevt\Logs\System.evtx" "EventLogs"
Copy-ForensicItem "$env:SystemRoot\System32\sru\SRUDB.dat" "SRUM"
Copy-ForensicItem "$env:APPDATA\Microsoft\Windows\Recent\*.lnk" "RecentLNK"
Copy-ForensicItem "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History" "Browser_Chrome"
Copy-ForensicItem "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default\History" "Browser_Edge"
Copy-ForensicItem "$env:SystemRoot\System32\drivers\etc\hosts" "Network"

$Manifest | ConvertTo-Json -Depth 3 | Out-File -Encoding UTF8 (Join-Path $OutDir "remote_triage_manifest.json")
$ZipPath = "$OutDir.zip"
Compress-Archive -Path "$OutDir\*" -DestinationPath $ZipPath -Force
Write-Output "DFIR Remote Triage Paketi Hazir: $ZipPath"
"""
        os.makedirs(os.path.dirname(os.path.abspath(output_ps1_path)) or ".", exist_ok=True)
        with open(output_ps1_path, "w", encoding="utf-8") as f:
            f.write(script)
        return output_ps1_path
