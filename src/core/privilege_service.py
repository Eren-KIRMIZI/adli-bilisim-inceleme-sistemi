"""Windows Privilege Inspection & Official UAC Elevation / Elevated Artifact Collector."""

import ctypes
import glob
import os
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional


class PrivilegeService:
    """Checks OS elevation status and collects locked Windows artifacts strictly via sanctioned OS paths."""

    @staticmethod
    def is_admin() -> bool:
        if os.name != "nt" or not hasattr(ctypes, "windll"):
            return False
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @classmethod
    def get_status(cls) -> Dict[str, Any]:
        is_win = os.name == "nt"
        admin = cls.is_admin()
        sys_evtx = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "winevt", "Logs", "System.evtx")
        pf_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch")

        evtx_readable = False
        pf_readable = False
        if is_win:
            try:
                with open(sys_evtx, "rb") as f:
                    f.read(8)
                evtx_readable = True
            except OSError:
                evtx_readable = False
            try:
                pf_readable = len(glob.glob(os.path.join(pf_dir, "*.pf"))) > 0
            except OSError:
                pf_readable = False

        return {
            "os": os.name,
            "is_admin": admin,
            "wevtutil_available": shutil.which("wevtutil") is not None,
            "live_evtx_accessible": evtx_readable,
            "live_prefetch_accessible": pf_readable,
            "guidance": (
                "Yönetici (Elevated) oturum aktif — canlı EVTX, Prefetch ve ham disk aygıtlarına erişilebilir."
                if admin
                else "Standart kullanıcı oturumu: Canlı System.evtx / Prefetch / PhysicalDrive erişimi için 'UAC Yönetici Modu' veya çevrimdışı imaj kullanın."
            ),
        }

    @classmethod
    def request_uac_elevation(cls, script_path: Optional[str] = None) -> Dict[str, Any]:
        """Prompt official Windows UAC consent to launch an elevated instance (user-initiated only)."""
        if os.name != "nt" or not hasattr(ctypes, "windll"):
            return {"launched": False, "error": "UAC yükseltme yalnızca Windows üzerinde desteklenir."}
        target = script_path or os.path.abspath(sys.argv[0])
        rc = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{target}"', os.getcwd(), 1)
        return {"launched": rc > 32, "shell_execute_code": int(rc)}

    @classmethod
    def collect_elevated_live_artifacts(cls, out_dir: str = "data/elevated_triage") -> Dict[str, Any]:
        """Collect read-only snapshots of live Windows Event Logs (wevtutil epl) and Prefetch (.pf)."""
        os.makedirs(out_dir, exist_ok=True)
        exported_evtx: List[str] = []
        copied_pf: List[str] = []
        errors: List[str] = []

        if os.name != "nt":
            return {"supported": False, "exported_evtx": [], "copied_pf": [], "errors": ["Yalnızca Windows."]}

        for ch in ("System", "Application", "Security"):
            dst = os.path.join(out_dir, f"Live_{ch}.evtx")
            if os.path.exists(dst):
                try:
                    os.remove(dst)
                except OSError:
                    pass
            res = subprocess.run(
                ["wevtutil", "epl", ch, dst],
                capture_output=True, text=True, timeout=20, check=False,
            )
            if res.returncode == 0 and os.path.isfile(dst):
                exported_evtx.append(dst)
            else:
                errors.append(f"{ch}.evtx ({res.stderr.strip() or f'kod={res.returncode}'})")

        pf_dir = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "Prefetch")
        if os.path.isdir(pf_dir):
            for pf in sorted(glob.glob(os.path.join(pf_dir, "*.pf")))[:15]:
                try:
                    dst = os.path.join(out_dir, os.path.basename(pf))
                    shutil.copy2(pf, dst)
                    copied_pf.append(dst)
                except OSError as exc:
                    errors.append(f"{os.path.basename(pf)}: {exc}")
                    break

        return {
            "supported": True,
            "is_admin": cls.is_admin(),
            "exported_evtx": exported_evtx,
            "copied_pf": copied_pf,
            "errors": errors,
        }
