"""Unit tests for USB forensic extraction engine."""

import pytest
from src.usb_engine.usb_service import UsbService

@pytest.fixture
def usb_service(tmp_path):
    db_file = str(tmp_path / "test_usb.db")
    return UsbService(db_path=db_file)

def test_list_devices(usb_service):
    devices = usb_service.list_devices()
    assert len(devices) >= 4
    vendors = [d.vendor for d in devices]
    assert "SanDisk" in vendors
    assert "Kingston" in vendors

def test_parse_usbstor_device_string(usb_service):
    ven, prod, rev = usb_service._parse_usbstor_device_string("Disk&Ven_SanDisk&Prod_Cruzer_Blade&Rev_1.26")
    assert ven == "SanDisk"
    assert prod == "Cruzer Blade"
    assert rev == "1.26"

def test_mark_suspicious(usb_service):
    devices = usb_service.list_devices()
    dev = devices[0]
    usb_service.mark_suspicious(dev.id, True, "Test anomaly note")
    
    updated = usb_service.get_device(dev.id)
    assert updated.is_suspicious is True
    assert "Test anomaly note" in updated.notes
