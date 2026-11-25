"""Tests for USB-Based Ed25519 Cryptographic Authentication, Lockout, AuditLog & PySide6 Login UI."""

import json
import os
import pytest

from src.core.usb_auth_service import UsbCryptoAuthService
from src.database.models import init_db, AuditLog
from src.ui.pages.usb_login_window import UsbLoginDialog


def test_usb_crypto_challenge_response_and_2fa(tmp_path):
    usb_dir = tmp_path / "usb_key_drive"
    usb_dir.mkdir()
    cfg_file = str(tmp_path / "usb_auth.json")
    db_file = str(tmp_path / "auth.db")

    svc = UsbCryptoAuthService(config_path=cfg_file, db_path=db_file, custom_usb_roots=[str(usb_dir)])
    assert svc.is_provisioned() is False
    assert svc.verify_usb_challenge()["state"] == "NO_PROVISION"

    prov = svc.provision_usb_key(str(usb_dir), "UnitTestSecret99!")
    assert prov["key_id"].startswith("KEY-ED25519-")
    assert svc.is_provisioned() is True

    # Verify private key file exists on USB and plaintext password is NOT stored in config
    assert os.path.isfile(usb_dir / ".forensic_key" / "usb_private_key.pem")
    cfg_txt = open(cfg_file, "r", encoding="utf-8").read()
    assert "UnitTestSecret99!" not in cfg_txt

    # Step 1: Challenge-response passes with provisioned USB
    res1 = svc.verify_usb_challenge()
    assert res1["verified"] is True
    assert res1["state"] == "SIGNATURE_VERIFIED"

    # Step 1 fails if USB is removed (empty root list)
    svc_removed = UsbCryptoAuthService(config_path=cfg_file, db_path=db_file, custom_usb_roots=[])
    assert svc_removed.verify_usb_challenge()["verified"] is False
    assert svc_removed.verify_usb_challenge()["state"] == "WAITING_USB"

    # Step 1 fails if forged/wrong private key is placed on another USB
    fake_usb = tmp_path / "fake_usb"
    fake_usb.mkdir()
    svc_fake = UsbCryptoAuthService(config_path=str(tmp_path / "other.json"), db_path=db_file, custom_usb_roots=[str(fake_usb)])
    svc_fake.provision_usb_key(str(fake_usb), "AnotherSecret11!")
    svc_mismatch = UsbCryptoAuthService(config_path=cfg_file, db_path=db_file, custom_usb_roots=[str(fake_usb)])
    assert svc_mismatch.verify_usb_challenge()["state"] == "CHALLENGE_FAILED"

    # Step 2: Wrong password 5 times triggers lockout; audit logs recorded
    for idx in range(4):
        bad = svc.verify_personal_password("WrongPass!", usb_verified=True)
        assert bad["authenticated"] is False and bad["locked"] is False
    locked_res = svc.verify_personal_password("WrongPass!", usb_verified=True)
    assert locked_res["authenticated"] is False and locked_res["locked"] is True
    assert svc.get_lockout_remaining() > 0

    # Reset lockout timestamp in local config for positive verification check
    cfg = json.loads(cfg_txt)
    cfg["lockout_until_epoch"] = 0.0
    cfg["failed_attempts"] = 0
    open(cfg_file, "w", encoding="utf-8").write(json.dumps(cfg))

    ok = svc.verify_personal_password("UnitTestSecret99!", usb_verified=True)
    assert ok["authenticated"] is True and len(ok["session_token"]) >= 32

    Session = init_db(db_file)
    with Session() as s:
        logs = s.query(AuditLog).all()
        assert any("USB-2FA Güvenli Oturum Başlatıldı" in l.action for l in logs)
        assert any("USB-2FA Başarısız Şifre Denemesi" in l.action for l in logs)


def test_usb_login_dialog_ui_flow(qapp, tmp_path):
    usb_dir = tmp_path / "usb_ui"
    usb_dir.mkdir()
    cfg_file = str(tmp_path / "ui_usb_auth.json")
    db_file = str(tmp_path / "ui_auth.db")

    svc = UsbCryptoAuthService(config_path=cfg_file, db_path=db_file, custom_usb_roots=[str(usb_dir)])
    svc.provision_usb_key(str(usb_dir), "UiTestPass2026!")

    # 1. Dialog with no USB attached -> password disabled
    dlg_wait = UsbLoginDialog(db_path=db_file, auth_config_path=cfg_file, custom_usb_roots=[], auto_poll=False)
    assert dlg_wait._usb_verified is False
    assert dlg_wait.pwd_input.isEnabled() is False
    assert dlg_wait.tile_auth_val.text() == "WAITING"
    dlg_wait.close()

    # 2. Dialog with valid USB attached -> digital signature verified -> password unlocks session
    dlg_ok = UsbLoginDialog(db_path=db_file, auth_config_path=cfg_file, custom_usb_roots=[str(usb_dir)], auto_poll=False)
    assert dlg_ok._usb_verified is True
    assert dlg_ok.pwd_input.isEnabled() is True
    assert dlg_ok.tile_auth_val.text() == "VERIFIED"
    dlg_ok.pwd_input.setText("UiTestPass2026!")
    dlg_ok._on_submit_password()
    assert dlg_ok.auth_result is not None and dlg_ok.auth_result["authenticated"] is True
    dlg_ok.close()
