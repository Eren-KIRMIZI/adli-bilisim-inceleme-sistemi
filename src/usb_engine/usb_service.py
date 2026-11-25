"""USB Device Forensics Engine adhering to NIST SP 800-86 standards."""

import os
import sys
import json
import re
from datetime import datetime
from typing import List, Dict, Any, Optional

from src.database.models import init_db, UsbDeviceRecord, Case, append_audit_log
from src.database.seed import seed_database_if_empty

# Try to import winreg on Windows
try:
    import winreg
    HAS_WINREG = True
except ImportError:
    HAS_WINREG = False

class UsbService:
    """Specialized engine for Windows USB artifact extraction and analysis."""

    def __init__(self, db_path="data/forensics.db"):
        self.Session = init_db(db_path)
        seed_database_if_empty(db_path)

    def list_devices(self, case_id: Optional[int] = None) -> List[UsbDeviceRecord]:
        """Fetch all parsed USB records, optionally filtered by case."""
        with self.Session() as s:
            q = s.query(UsbDeviceRecord)
            if case_id:
                q = q.filter(UsbDeviceRecord.case_id == case_id)
            return q.order_by(UsbDeviceRecord.is_suspicious.desc(), UsbDeviceRecord.last_connected.desc()).all()

    def get_device(self, device_id: int) -> Optional[UsbDeviceRecord]:
        """Fetch single device record by ID."""
        with self.Session() as s:
            return s.query(UsbDeviceRecord).filter(UsbDeviceRecord.id == device_id).first()

    def scan_live_system(self, case_id: int = 1) -> List[UsbDeviceRecord]:
        """Extract USB device artifacts directly from the live Windows Registry.
        Adheres to Read-Only extraction without modifying registry keys.
        """
        extracted_records: List[UsbDeviceRecord] = []
        if not HAS_WINREG:
            return extracted_records

        # Map MountedDevices to drive letters
        mounted_map = self._get_mounted_devices_map()

        try:
            # 1. Parse HKLM\SYSTEM\CurrentControlSet\Enum\USBSTOR
            usbstor_path = r"SYSTEM\CurrentControlSet\Enum\USBSTOR"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, usbstor_path, 0, winreg.KEY_READ) as usbstor_key:
                num_subkeys, _, _ = winreg.QueryInfoKey(usbstor_key)
                for i in range(num_subkeys):
                    try:
                        device_type_key_name = winreg.EnumKey(usbstor_key, i)
                        # device_type_key_name format: Disk&Ven_Vendor&Prod_Product&Rev_Revision
                        vendor, product, rev = self._parse_usbstor_device_string(device_type_key_name)

                        device_subpath = f"{usbstor_path}\\{device_type_key_name}"
                        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, device_subpath, 0, winreg.KEY_READ) as dev_key:
                            num_instances, _, _ = winreg.QueryInfoKey(dev_key)
                            for j in range(num_instances):
                                try:
                                    serial_name = winreg.EnumKey(dev_key, j)
                                    # Serial numbers may have &0 suffix if not unique
                                    instance_path = f"{device_subpath}\\{serial_name}"
                                    
                                    details = {}
                                    with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, instance_path, 0, winreg.KEY_READ) as inst_key:
                                        num_values, _, _ = winreg.QueryInfoKey(inst_key)
                                        for v in range(num_values):
                                            try:
                                                vname, vdata, _ = winreg.EnumValue(inst_key, v)
                                                details[vname] = vdata
                                            except Exception:
                                                pass

                                    friendly_name = details.get("FriendlyName", f"{vendor} {product}")
                                    drive_letter = mounted_map.get(serial_name.split("&")[0], None)
                                    vid_m = re.search(r"VID_([0-9A-Fa-f]{4})", str(details.get("HardwareID", "")) + str(details.get("ContainerID", "")))
                                    pid_m = re.search(r"PID_([0-9A-Fa-f]{4})", str(details.get("HardwareID", "")))

                                    rec = UsbDeviceRecord(
                                        case_id=case_id,
                                        device_name=str(friendly_name),
                                        vendor=vendor,
                                        product=product,
                                        revision=rev,
                                        vid=vid_m.group(1).upper() if vid_m else None,
                                        pid=pid_m.group(1).upper() if pid_m else None,
                                        serial_number=serial_name,
                                        drive_letter=drive_letter,
                                        first_connected=None,  # winreg canlı taraması alt anahtar FILETIME zamanını döndürmez; uydurulmaz
                                        last_connected=None,
                                        registry_source_key=instance_path,
                                        device_class="USBSTOR",
                                        status="İnceleniyor",
                                        confidence=85,
                                        is_suspicious=False,
                                        notes="Canlı Windows Registry (USBSTOR) üzerinden salt-okunur okundu. Zaman damgaları çevrimdışı SYSTEM kovanından çıkarılmalıdır.",
                                        raw_details=json.dumps(details, default=str)
                                    )
                                    extracted_records.append(rec)
                                except Exception:
                                    continue
                    except Exception:
                        continue
        except Exception:
            pass

        # Save to database with hash-chained AuditLog
        if extracted_records:
            with self.Session() as s:
                s.add_all(extracted_records)
                append_audit_log(
                    s,
                    case_id,
                    "Canlı Analiz Motoru",
                    "Canlı USB Taraması Tamamlandı",
                    f"Canlı sistemden {len(extracted_records)} adet USBSTOR kaydı salt-okunur çıkarıldı.",
                )
                s.commit()
                for rec in extracted_records:
                    s.refresh(rec)

        return extracted_records

    def _get_mounted_devices_map(self) -> Dict[str, str]:
        """Extract mapping between drive letters and serials from MountedDevices."""
        mapping = {}
        if not HAS_WINREG:
            return mapping
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\MountedDevices", 0, winreg.KEY_READ) as key:
                num_values, _, _ = winreg.QueryInfoKey(key)
                for i in range(num_values):
                    vname, vdata, _ = winreg.EnumValue(key, i)
                    if vname.startswith("\\DosDevices\\"):
                        letter = vname.replace("\\DosDevices\\", "")
                        if isinstance(vdata, bytes):
                            text = vdata.decode("utf-16le", errors="ignore")
                            # text contains e.g. _??_USBSTOR#Disk&Ven_...#SerialNumber#{guid}
                            match = re.search(r"#([^#]+)#{", text)
                            if match:
                                serial = match.group(1).split("&")[0]
                                mapping[serial] = letter
        except Exception:
            pass
        return mapping

    def _parse_usbstor_device_string(self, text: str):
        vendor = "Bilinmeyen Üretici"
        product = "USB Cihazı"
        rev = ""
        m_ven = re.search(r"Ven_([a-zA-Z0-9_\-\.]+)", text)
        if m_ven:
            vendor = m_ven.group(1).replace("_", " ").strip()
        m_prod = re.search(r"Prod_([a-zA-Z0-9_\-\.]+)", text)
        if m_prod:
            product = m_prod.group(1).replace("_", " ").strip()
        m_rev = re.search(r"Rev_([a-zA-Z0-9_\-\.]+)", text)
        if m_rev:
            rev = m_rev.group(1).replace("_", " ").strip()
        return vendor, product, rev

    def parse_offline_hive(self, hive_path: str, case_id: int = 1) -> List[UsbDeviceRecord]:
        """Read and parse offline SYSTEM registry hive via regf parser (falling back honestly without fabricating metadata)."""
        extracted: List[UsbDeviceRecord] = []
        if not os.path.exists(hive_path):
            return extracted

        # 1. Preferred path: Structural regf parsing via RegistryHiveParser (extracts real key timestamps & serials)
        try:
            from src.registry_engine.hive_parser import RegistryHiveParser
            parsed = RegistryHiveParser().parse_hive_file(hive_path)
            root = parsed.get("root")

            def walk_usbstor(node: Dict[str, Any]):
                npath = node.get("path", "")
                nname = node.get("name", "")
                if "usbstor" in npath.lower() and "Ven_" in nname and "Prod_" in nname:
                    ven, prod, rev = self._parse_usbstor_device_string(nname)
                    for inst in node.get("children", []):
                        vals = {v["name"]: v["value"] for v in inst.get("values", [])}
                        fname = vals.get("FriendlyName") or f"{ven} {prod}"
                        extracted.append(UsbDeviceRecord(
                            case_id=case_id,
                            device_name=str(fname),
                            vendor=ven,
                            product=prod,
                            revision=rev or None,
                            vid=None,
                            pid=None,
                            serial_number=inst.get("name") or None,
                            drive_letter=None,  # MountedDevices eşleşmesi ayrı kanıt gerektirir
                            first_connected=None,
                            last_connected=inst.get("last_written"),
                            registry_source_key=inst.get("path", npath),
                            device_class="USBSTOR",
                            status="İnceleniyor",
                            confidence=90,
                            is_suspicious=False,
                            notes=f"Çevrimdışı regf kovanı ({os.path.basename(hive_path)}) içinden ayrıştırıldı.",
                        ))
                for ch in node.get("children", []):
                    walk_usbstor(ch)

            if root:
                walk_usbstor(root)
        except Exception:
            extracted = []

        # 2. Fallback: raw string discovery when hive is unindexed/partial (never fabricate serial/drive/timestamp)
        if not extracted:
            with open(hive_path, "rb") as f:
                data = f.read(min(os.path.getsize(hive_path), 64 * 1024 * 1024))

            matches = re.findall(rb"Disk&Ven_([a-zA-Z0-9_\-\.]+)&Prod_([a-zA-Z0-9_\-\.]+)", data)
            seen = set()
            for m in matches:
                ven = m[0].decode("ascii", "replace").replace("_", " ").strip()
                prod = m[1].decode("ascii", "replace").replace("_", " ").strip()
                key = (ven, prod)
                if key in seen:
                    continue
                seen.add(key)

                extracted.append(UsbDeviceRecord(
                    case_id=case_id,
                    device_name=f"{ven} {prod}",
                    vendor=ven,
                    product=prod,
                    revision=None,
                    vid=None,
                    pid=None,
                    serial_number=None,
                    drive_letter=None,
                    first_connected=None,
                    last_connected=None,
                    registry_source_key=f"HIVE_RAW\\{os.path.basename(hive_path)}\\USBSTOR",
                    device_class="USBSTOR",
                    status="Kısmi (Ham Dize)",
                    confidence=45,
                    is_suspicious=False,
                    notes=(
                        f"Uyarı: {os.path.basename(hive_path)} tam regf ağacı olarak çözülemedi; "
                        "yalnızca ham baytlardan USBSTOR üretici/model dizesi çıkarıldı (seri/sürücü/zaman bilinmiyor)."
                    ),
                ))

        if extracted:
            with self.Session() as s:
                s.add_all(extracted)
                append_audit_log(
                    s,
                    case_id,
                    "USB Analiz Motoru",
                    "Çevrimdışı Hive USB Analizi",
                    f"{os.path.basename(hive_path)} içinden {len(extracted)} USB kaydı çıkarıldı.",
                )
                s.commit()
                for rec in extracted:
                    s.refresh(rec)

        return extracted

    def mark_suspicious(self, device_id: int, is_suspicious: bool = True, notes: str = ""):
        with self.Session() as s:
            dev = s.query(UsbDeviceRecord).filter(UsbDeviceRecord.id == device_id).first()
            if dev:
                dev.is_suspicious = is_suspicious
                dev.status = "Şüpheli Cihaz" if is_suspicious else "Normal"
                if notes:
                    dev.notes = (dev.notes or "") + f"\n[Not]: {notes}"
                s.commit()
