"""Forensic seed generator with realistic NIST-compliant digital investigation data."""

from datetime import datetime, timedelta
import json
from src.database.models import (
    init_db, Case, Evidence, UsbDeviceRecord, AuditLog, ChainOfCustodyEntry
)

def seed_database_if_empty(db_path="data/forensics.db"):
    Session = init_db(db_path)
    with Session() as s:
        if s.query(Case).first() is not None:
            # Ensure chain_of_custody has initial records if upgrading an existing seeded DB
            if s.query(ChainOfCustodyEntry).first() is None:
                evds = s.query(Evidence).all()
                for evd in evds:
                    s.add(ChainOfCustodyEntry(
                        case_id=evd.case_id,
                        evidence_id=evd.id,
                        timestamp=evd.acquire_date or datetime.utcnow(),
                        action_type="Teslim Alındı & İmaj Doğrulandı",
                        delivered_by="Olay Yeri Ekibi",
                        received_by=evd.custodian or "Adli Bilişim Uzmanı",
                        location="Adli Bilişim Laboratuvarı - Kasa 01",
                        acquire_method="Fiziksel Adli İmaj (Salt Okunur)",
                        write_blocker_info=evd.acquire_tool or "Donanımsal Yazma Engelleyici",
                        sha256_at_event=evd.sha256_hash,
                        sha512_at_event=evd.sha512_hash,
                        verification_status="Doğrulandı",
                        notes=evd.notes or "İlk kabul sırasında hash bütünlüğü doğrulandı."
                    ))
                s.commit()
            return

        # 1. Create Primary Forensic Case
        case = Case(
            case_number="VAK-2026-084",
            title="Yetkisiz Veri Sızıntısı ve USB Cihaz İncelemesi",
            investigator="Adli Bilişim Uzmanı E. Kırmızı",
            organization="Siber Olay Müdahale ve Adli İnceleme Birimi",
            description="Şüpheli uç noktada yetkisiz veri aktarımı şüphesiyle alınan adli imaj ve bağlanan USB belleklerin analizi.",
            status="open",
            opened_at=datetime.utcnow() - timedelta(days=2)
        )
        s.add(case)
        s.flush()

        # 2. Create Evidences
        e1 = Evidence(
            case_id=case.id,
            evidence_number="EVD-2026-001",
            device_type="USB Flash Bellek",
            brand="SanDisk",
            model="Cruzer Blade USB 2.0",
            serial="4C530001250912117441",
            capacity_bytes=32 * 1024 * 1024 * 1024,
            acquire_date=datetime.utcnow() - timedelta(days=2),
            custodian="Güvenlik Amiri M. Demir",
            acquire_tool="Tableau T8u USB 3.0 Forensic Bridge",
            write_blocker_used=True,
            sha256_hash="7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069",
            sha512_hash="a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e29783965b796ad37768565b93d3958ee1e2a8c3d2e13e2f5b0266453f6055d0a",
            status="verified",
            notes="Donanımsal yazma engelleyici kullanılarak fiziki imajı alındı. Hash eşleşti."
        )

        e2 = Evidence(
            case_id=case.id,
            evidence_number="EVD-2026-002",
            device_type="USB Flash Bellek",
            brand="Kingston",
            model="DataTraveler 3.0",
            serial="0014D1185292F9B0B71B08C7",
            capacity_bytes=64 * 1024 * 1024 * 1024,
            acquire_date=datetime.utcnow() - timedelta(days=1),
            custodian="Adli Bilişim Uzmanı E. Kırmızı",
            acquire_tool="Tableau T8u",
            write_blocker_used=True,
            sha256_hash="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            status="verified",
            notes="Delil muhafaza torbasında teslim alındı."
        )

        e3 = Evidence(
            case_id=case.id,
            evidence_number="EVD-2026-003",
            device_type="Taşınabilir NVMe SSD",
            brand="Samsung",
            model="Portable SSD T7 500GB",
            serial="S5B4NX0R812345K",
            capacity_bytes=500 * 1024 * 1024 * 1024,
            acquire_date=datetime.utcnow() - timedelta(hours=14),
            custodian="Adli Bilişim Uzmanı E. Kırmızı",
            acquire_tool="Atola TaskForce Forensic Imager",
            write_blocker_used=True,
            sha256_hash="15e2b0d3c33891ebb0f1ef609ec419420c20e320ce94c65fbc8c3312448eb225",
            status="analyzing",
            notes="Hızlı veri kopyalama amacıyla kullanılan harici disk."
        )

        s.add_all([e1, e2, e3])
        s.flush()

        # 3. Chain of Custody Records
        custody_records = [
            ChainOfCustodyEntry(
                case_id=case.id,
                evidence_id=e1.id,
                timestamp=datetime.utcnow() - timedelta(days=2),
                action_type="Teslim Alındı",
                delivered_by="Güvenlik Amiri M. Demir",
                received_by="Adli Bilişim Uzmanı E. Kırmızı",
                location="Laboratuvar Delil Kabul Masası",
                acquire_method="Mühürlü Delil Torbası #TB-991",
                write_blocker_info="Tableau T8u USB 3.0 Forensic Bridge",
                sha256_at_event=e1.sha256_hash,
                sha512_at_event=e1.sha512_hash,
                verification_status="Doğrulandı",
                notes="Fiziksel mühür sağlam. Salt-okunur adli imaj alma başlatıldı."
            ),
            ChainOfCustodyEntry(
                case_id=case.id,
                evidence_id=e1.id,
                timestamp=datetime.utcnow() - timedelta(days=2, hours=-2),
                action_type="İmaj Alındı & Hash Doğrulandı",
                delivered_by="Adli Bilişim Uzmanı E. Kırmızı",
                received_by="Çalışma Kopyası Sunucusu (Salt Okunur)",
                location="Analiz İstasyonu #02",
                acquire_method="RAW Bitstream İmaj (.dd)",
                write_blocker_info="Tableau T8u Hardware Write-Blocker",
                sha256_at_event=e1.sha256_hash,
                sha512_at_event=e1.sha512_hash,
                verification_status="Doğrulandı",
                notes="Kaynak ve hedef SHA-256 / SHA-512 hash değerleri %100 eşleşti."
            ),
            ChainOfCustodyEntry(
                case_id=case.id,
                evidence_id=e2.id,
                timestamp=datetime.utcnow() - timedelta(days=1),
                action_type="Teslim Alındı & Hash Doğrulandı",
                delivered_by="Olay Yeri Müdahale Ekibi",
                received_by="Adli Bilişim Uzmanı E. Kırmızı",
                location="Laboratuvar Delil Kasası #01",
                acquire_method="Fiziksel Teslim",
                write_blocker_info="Tableau T8u",
                sha256_at_event=e2.sha256_hash,
                verification_status="Doğrulandı",
                notes="Delil muhafaza zinciri başlatıldı."
            ),
            ChainOfCustodyEntry(
                case_id=case.id,
                evidence_id=e3.id,
                timestamp=datetime.utcnow() - timedelta(hours=14),
                action_type="İncelemeye Çıktı",
                delivered_by="Delil Kasası #01",
                received_by="Adli Bilişim Uzmanı E. Kırmızı",
                location="Analiz İstasyonu #01",
                acquire_method="Atola TaskForce E01",
                write_blocker_info="Atola Entegre Yazma Engelleyici",
                sha256_at_event=e3.sha256_hash,
                verification_status="Doğrulandı",
                notes="Çalışma kopyası üzerinde dosya sistemi ve USB korelasyonu yürütülüyor."
            ),
        ]
        s.add_all(custody_records)

        # 4. Create USB Forensic Records
        usb1 = UsbDeviceRecord(
            case_id=case.id,
            evidence_id=e1.id,
            device_name="SanDisk Cruzer Blade USB Device",
            vendor="SanDisk",
            product="Cruzer Blade",
            revision="1.26",
            vid="0781",
            pid="5567",
            serial_number="4C530001250912117441",
            drive_letter="E:",
            volume_guid="{a78b5e20-3011-11ee-8c44-00155d011200}",
            first_connected=datetime.utcnow() - timedelta(days=5, hours=3),
            last_connected=datetime.utcnow() - timedelta(days=1, hours=2),
            last_removed=datetime.utcnow() - timedelta(days=1, hours=1, minutes=45),
            user_account="AhmetK (Finans)",
            user_sid="S-1-5-21-1234567890-987654321-1001",
            registry_source_key=r"SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.26\4C530001250912117441",
            device_class="USBSTOR",
            status="Normal",
            confidence=100,
            is_suspicious=False,
            notes="Kullanıcı profili MountPoints2 ve MountedDevices kayıtlarıyla tam örtüşüyor.",
            raw_details=json.dumps({
                "HardwareID": "USBSTOR\\DiskSanDisk_Cruzer_Blade___1.26",
                "CompatibleIDs": ["USBSTOR\\Disk", "USBSTOR\\RAW"],
                "FriendlyName": "SanDisk Cruzer Blade USB Device",
                "DeviceDesc": "@disk.inf,%disk_devdesc%;Disk sürücüsü"
            })
        )

        usb2 = UsbDeviceRecord(
            case_id=case.id,
            evidence_id=e2.id,
            device_name="Kingston DataTraveler 3.0",
            vendor="Kingston",
            product="DataTraveler 3.0",
            revision="PMAP",
            vid="0951",
            pid="1666",
            serial_number="0014D1185292F9B0B71B08C7",
            drive_letter="F:",
            volume_guid="{c4217f90-3022-11ee-9011-00155d011400}",
            first_connected=datetime.utcnow() - timedelta(days=3, hours=7),
            last_connected=datetime.utcnow() - timedelta(hours=8),
            last_removed=datetime.utcnow() - timedelta(hours=7, minutes=50),
            user_account="AhmetK (Finans)",
            user_sid="S-1-5-21-1234567890-987654321-1001",
            registry_source_key=r"SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_Kingston&Prod_DataTraveler_3.0&Rev_PMAP\0014D1185292F9B0B71B08C7",
            device_class="USBSTOR",
            status="Doğrulandı",
            confidence=100,
            is_suspicious=False,
            notes="EventLog 2003/2004 sürücü yükleme ve bağlantı loglarıyla doğrulandı.",
            raw_details=json.dumps({
                "HardwareID": "USBSTOR\\DiskKingstonDataTraveler_3.0PMAP",
                "CompatibleIDs": ["USBSTOR\\Disk"],
                "FriendlyName": "Kingston DataTraveler 3.0 USB Device"
            })
        )

        usb3 = UsbDeviceRecord(
            case_id=case.id,
            evidence_id=e3.id,
            device_name="Samsung PSSD T7 SCSI Disk Device",
            vendor="Samsung",
            product="PSSD T7",
            revision="0",
            vid="04E8",
            pid="61F5",
            serial_number="S5B4NX0R812345K",
            drive_letter="G:",
            volume_guid="{e11234a0-3025-11ee-8212-00155d011800}",
            first_connected=datetime.utcnow() - timedelta(hours=14),
            last_connected=datetime.utcnow() - timedelta(hours=12, minutes=10),
            last_removed=datetime.utcnow() - timedelta(hours=12, minutes=2),
            user_account="MehmetS (Sistem Yöneticisi)",
            user_sid="S-1-5-21-1234567890-987654321-1002",
            registry_source_key=r"SYSTEM\CurrentControlSet\Enum\USBSTOR\Disk&Ven_Samsung&Prod_PSSD_T7&Rev_0\S5B4NX0R812345K",
            device_class="USBSTOR",
            status="İnceleniyor",
            confidence=95,
            is_suspicious=False,
            notes="Mesai bitimi saat 19:42'de 120 GB veri transferi tespit edildi.",
            raw_details=json.dumps({
                "HardwareID": "USBSTOR\\DiskSamsung_PSSD_T7_________0",
                "FriendlyName": "Samsung PSSD T7 SCSI Disk Device"
            })
        )

        usb_suspicious = UsbDeviceRecord(
            case_id=case.id,
            evidence_id=None,
            device_name="USB Rubber Ducky / BadUSB HID Keystroke Injector",
            vendor="Atmel Corp. / Hak5",
            product="HID Keyboard / Payload Injector",
            revision="1.00",
            vid="03EB",
            pid="2043",
            serial_number="000000000001",
            drive_letter=None,
            volume_guid=None,
            first_connected=datetime.utcnow() - timedelta(days=2, hours=1),
            last_connected=datetime.utcnow() - timedelta(days=2, hours=1),
            last_removed=datetime.utcnow() - timedelta(days=2, hours=0, minutes=45),
            user_account="SYSTEM",
            user_sid="S-1-5-18",
            registry_source_key=r"SYSTEM\CurrentControlSet\Enum\USB\VID_03EB&PID_2043\000000000001",
            device_class="HID / Şüpheli Enjektör",
            status="Şüpheli Cihaz",
            confidence=90,
            is_suspicious=True,
            notes="⚠️ DİKKAT: Cihaz HID klavye olarak tanıtılmış ve 15 saniye içinde powershell scripti çalıştırmıştır.",
            raw_details=json.dumps({
                "HardwareID": "USB\\VID_03EB&PID_2043&REV_0100",
                "CompatibleIDs": ["USB\\Class_03&SubClass_01&Prot_01"],
                "DeviceDesc": "HID Klavye Aygıtı (Sahte)",
                "Service": "kbdhid"
            })
        )

        s.add_all([usb1, usb2, usb3, usb_suspicious])

        # 5. Create Audit Logs
        logs = [
            AuditLog(
                case_id=case.id,
                timestamp=datetime.utcnow() - timedelta(days=2),
                investigator="Adli Bilişim Uzmanı E. Kırmızı",
                action="Vaka Oluşturuldu",
                details="VAK-2026-084 numaralı soruşturma açıldı. Delil muhafaza zinciri başlatıldı.",
                verification_hash="b823f79883478cbef1a19001b97ad8"
            ),
            AuditLog(
                case_id=case.id,
                timestamp=datetime.utcnow() - timedelta(days=2, hours=-1),
                investigator="Adli Bilişim Uzmanı E. Kırmızı",
                action="Delil Kabul & Hash Doğrulama",
                details="EVD-2026-001 (SanDisk Cruzer) kabul edildi. SHA-256 doğrulandı.",
                verification_hash="7f83b1657ff1fc53b92dc18148a1d65d"
            ),
            AuditLog(
                case_id=case.id,
                timestamp=datetime.utcnow() - timedelta(days=1),
                investigator="Adli Bilişim Uzmanı E. Kırmızı",
                action="USBSTOR Kayıtları Ayrıştırıldı",
                details="SYSTEM Registry kovanı ayrıştırıldı. 4 adet USB cihazı tespit edildi.",
                verification_hash="4a90f117ce4599a0cb90141b7cd9140"
            ),
            AuditLog(
                case_id=case.id,
                timestamp=datetime.utcnow() - timedelta(hours=3),
                investigator="Adli Bilişim Uzmanı E. Kırmızı",
                action="Şüpheli Cihaz Tespiti",
                details="VID_03EB&PID_2043 (BadUSB) anomalisi işaretlendi ve öncelikli analiz sırasına alındı.",
                verification_hash="99ce145ad8b971480fca017409cc321"
            )
        ]
        s.add_all(logs)
        s.commit()
