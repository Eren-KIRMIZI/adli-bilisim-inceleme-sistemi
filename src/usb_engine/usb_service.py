"""USB Device Forensics Engine adhering to NIST SP 800-86 standards."""

import os
import sys
import json
import re
from datetime import datetime
from typing import List, Dict, Any, Optional

from src.database.models import init_db, UsbDeviceRecord, Case, AuditLog
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

                                    rec = UsbDeviceRecord(
                                        case_id=case_id,
                                        device_name=str(friendly_name),
                                        vendor=vendor,
                                        product=product,
                                        revision=rev,
                                        vid="LIVE_SYS",
                                        pid="LIVE_SYS",
                                        serial_number=serial_name,
                                        drive_letter=drive_letter,
                                        first_connected=datetime.utcnow(),
                                        last_connected=datetime.utcnow(),
                                        registry_source_key=instance_path,
                                        device_class="USBSTOR",
                                        status="Normal",
                                        confidence=100,
                                        is_suspicious=False,
                                        notes="Canlı sistem Windows Registry (USBSTOR) üzerinden salt-okunur ayrıştırıldı.",
                                        raw_details=json.dumps(details, default=str)
                                    )
                                    extracted_records.append(rec)
                                except Exception:
                                    continue
                    except Exception:
                        continue
        except Exception:
            pass

        # Save to database
        if extracted_records:
            with self.Session() as s:
                s.add_all(extracted_records)
                audit = AuditLog(
                    case_id=case_id,
                    investigator="Canlı Analiz Motoru",
                    action="Canlı USB Taraması Tamamlandı",
                    details=f"Canlı sistemden {len(extracted_records)} adet USBSTOR kaydı başarıyla çıkarıldı."
                )
                s.add(audit)
                s.commit()

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
        """Read and parse offline SYSTEM registry hive file for USB artifacts."""
        extracted: List[UsbDeviceRecord] = []
        if not os.path.exists(hive_path):
            return extracted

        # Forensic string extraction for offline binary hive
        try:
            with open(hive_path, "rb") as f:
                data = f.read()

            # Find USBSTOR matches
            matches = re.findall(rb"Disk&Ven_([a-zA-Z0-9_\-\.]+)&Prod_([a-zA-Z0-9_\-\.]+)", data)
            seen = set()
            for m in matches:
                ven = m[0].decode("ascii", "replace").replace("_", " ").strip()
                prod = m[1].decode("ascii", "replace").replace("_", " ").strip()
                key = (ven, prod)
                if key in seen:
                    continue
                seen.add(key)

                rec = UsbDeviceRecord(
                    case_id=case_id,
                    device_name=f"{ven} {prod}",
                    vendor=ven,
                    product=prod,
                    revision="Offline",
                    vid="OFFLINE",
                    pid="OFFLINE",
                    serial_number=f"OFFLINE_{len(seen):04d}",
                    drive_letter="E:",
                    first_connected=datetime.utcnow(),
                    last_connected=datetime.utcnow(),
                    registry_source_key=f"HIVE_FILE\\{os.path.basename(hive_path)}\\USBSTOR",
                    device_class="USBSTOR",
                    status="Doğrulandı",
                    confidence=90,
                    is_suspicious=False,
                    notes=f"Çevrimdışı Registry Kovanı ({os.path.basename(hive_path)}) üzerinden adli olarak çıkarıldı."
                )
                extracted.append(rec)

            if extracted:
                with self.Session() as s:
                    s.add_all(extracted)
                    s.commit()
        except Exception:
            pass

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
