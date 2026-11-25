"""USB-Based Cryptographic Two-Factor Authentication Gate (Ed25519 Challenge-Response + Personal Password)."""

import math
from typing import Any, Dict, Optional

from PySide6.QtCore import Qt, QTimer, QRectF, QPointF
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPen, QBrush, QPainterPath
from PySide6.QtWidgets import (
    QDialog, QWidget, QHBoxLayout, QVBoxLayout, QLabel, QFrame,
    QLineEdit, QPushButton, QComboBox, QFormLayout, QMessageBox
)

from src.core.usb_auth_service import UsbCryptoAuthService
from src.ui.styles.icons import get_app_icon, get_brand_pixmap


class UsbKeyAnimationWidget(QWidget):
    """Animated QPainter USB Security Key silhouette with Morse/dot signal pulses inspired by FIDO2 keys."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumSize(460, 175)
        self._state = "WAITING_USB"  # WAITING_USB, USB_NO_KEY, SIGNATURE_VERIFIED, CHALLENGE_FAILED, LOCKED
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.setInterval(45)
        self._timer.timeout.connect(self._tick)
        self._timer.start()

    def set_auth_state(self, state: str) -> None:
        self._state = state
        self.update()

    def _tick(self) -> None:
        self._phase = (self._phase + 0.14) % (2.0 * math.pi)
        self.update()

    def paintEvent(self, event) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        w, h = self.width(), self.height()
        cx, cy = w / 2.0, h / 2.0
        pulse = 0.5 + 0.5 * math.sin(self._phase)

        if self._state == "SIGNATURE_VERIFIED":
            accent = QColor("#10B981")
            glow = QColor(16, 185, 129, int(45 + 35 * pulse))
        elif self._state in ("CHALLENGE_FAILED", "LOCKED"):
            accent = QColor("#EF4444")
            glow = QColor(239, 68, 68, int(45 + 45 * pulse))
        elif self._state == "USB_NO_KEY":
            accent = QColor("#F59E0B")
            glow = QColor(245, 158, 11, int(40 + 35 * pulse))
        else:
            accent = QColor("#38BDF8")
            glow = QColor(56, 189, 248, int(35 + 45 * pulse))

        # Subtle outer concentric halo
        for idx, rad in enumerate((76 + 8 * pulse, 58 + 4 * pulse)):
            ring_col = QColor(accent)
            ring_col.setAlpha(28 if idx == 0 else 55)
            p.setPen(QPen(ring_col, 1.4))
            p.setBrush(Qt.NoBrush)
            p.drawEllipse(QPointF(cx, cy - 6), rad, rad)

        # Radial glow behind USB key
        p.setPen(Qt.NoPen)
        p.setBrush(glow)
        p.drawEllipse(QPointF(cx, cy - 6), 50, 50)

        # Side Morse/signal dot clusters (like FIDO2 prompt aesthetic)
        dot_patterns = [
            (-135, -30, [4, 2, 2, 4, 2]),
            (-92, 6, [5, 5, 5]),
            (92, 6, [5, 5, 5]),
            (135, -30, [2, 4, 2, 2, 4]),
            (-115, 36, [2, 2, 2, 2]),
            (115, 36, [2, 2, 2, 2]),
        ]
        for bx, by, radii in dot_patterns:
            cur_x = cx + bx - (len(radii) * 7) / 2.0
            for j, r in enumerate(radii):
                wave = 0.35 + 0.65 * (0.5 + 0.5 * math.sin(self._phase * 1.5 + j * 0.8 + bx * 0.05))
                dc = QColor(accent if (j % 2 == 0 or self._state == "SIGNATURE_VERIFIED") else "#64748B")
                dc.setAlpha(int(90 + 165 * wave))
                p.setBrush(dc)
                p.drawEllipse(QPointF(cur_x + j * 9, cy + by), r, r)

        # USB Security Key Body
        key_w, key_h = 54.0, 74.0
        kx, ky = cx - key_w / 2.0, cy - key_h / 2.0 - 12.0
        body_rect = QRectF(kx, ky, key_w, key_h)
        grad = QLinearGradient(kx, ky, kx + key_w, ky + key_h)
        grad.setColorAt(0.0, QColor("#1E293B"))
        grad.setColorAt(1.0, QColor("#0F172A"))
        p.setBrush(QBrush(grad))
        p.setPen(QPen(accent, 2.2))
        p.drawRoundedRect(body_rect, 24.0, 24.0)

        # Keyring hole or Checkmark inside top circle
        ring_center = QPointF(cx, ky + 22.0)
        p.setPen(QPen(accent, 2.0))
        p.setBrush(QColor("#0B1117"))
        p.drawEllipse(ring_center, 9.5, 9.5)

        if self._state == "SIGNATURE_VERIFIED":
            chk = QPainterPath()
            chk.moveTo(cx - 4.5, ky + 22.0)
            chk.lineTo(cx - 1.2, ky + 25.2)
            chk.lineTo(cx + 5.0, ky + 18.8)
            p.setPen(QPen(QColor("#10B981"), 2.3, Qt.SolidLine, Qt.RoundCap, Qt.RoundJoin))
            p.drawPath(chk)

        # Bottom LED bar inside USB body
        led_rect = QRectF(cx - 12.0, ky + key_h - 22.0, 24.0, 5.0)
        led_col = QColor(accent)
        led_col.setAlpha(int(140 + 115 * pulse))
        p.setPen(Qt.NoPen)
        p.setBrush(led_col)
        p.drawRoundedRect(led_rect, 2.5, 2.5)

        # USB-A Metal Connector Pins
        plug_w, plug_h = 34.0, 22.0
        px, py = cx - plug_w / 2.0, ky + key_h
        p.setBrush(QColor("#111827"))
        p.setPen(QPen(accent, 2.0))
        p.drawRoundedRect(QRectF(px, py, plug_w, plug_h), 3.0, 3.0)
        for pin_x in (cx - 9.0, cx - 3.0, cx + 3.0, cx + 9.0):
            p.setPen(QPen(accent, 1.8))
            p.drawLine(QPointF(pin_x, py + 4.0), QPointF(pin_x, py + plug_h - 4.0))


class ProvisionUsbDialog(QDialog):
    """First-time setup dialog to bind a removable USB drive + personal password when unprovisioned."""

    def __init__(self, auth_service: UsbCryptoAuthService, parent=None):
        super().__init__(parent)
        self.auth_service = auth_service
        self.setWindowTitle("USB Güvenlik Anahtarı İlk Kurulumu")
        self.setMinimumWidth(460)
        self.setStyleSheet(
            "QDialog { background: #0B1117; color: #E5E7EB; }"
            "QLabel { color: #CBD5E1; font-size: 12px; }"
            "QLineEdit, QComboBox { background: #111827; color: #F9FAFB; border: 1px solid #334155; border-radius: 6px; padding: 8px; }"
            "QPushButton { background: #1E293B; color: #E5E7EB; border: 1px solid #334155; border-radius: 6px; padding: 8px 14px; font-weight: 600; }"
            "QPushButton#primaryBtn { background: #0284C7; border-color: #38BDF8; color: #FFFFFF; }"
        )

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 20, 20, 20)
        lay.setSpacing(12)

        title = QLabel("🔐 Yeni USB Güvenlik Anahtarı (Ed25519) Oluştur")
        title.setStyleSheet("font-size: 15px; font-weight: 700; color: #38BDF8;")
        lay.addWidget(title)

        form = QFormLayout()
        form.setSpacing(10)

        self.drive_combo = QComboBox()
        drives = self.auth_service.detect_usb_drives()
        for d in drives:
            self.drive_combo.addItem(f"{d['label']} ({d['drive_letter']}) • {d['capacity_gb']}", d["root"])
        if not drives:
            self.drive_combo.addItem("Takılı USB sürücüsü bulunamadı", "")
        form.addRow("Hedef USB Sürücüsü:", self.drive_combo)

        self.op_input = QLineEdit("Adli Bilişim Uzmanı E. Kırmızı")
        form.addRow("Operatör Adı:", self.op_input)

        self.pwd1 = QLineEdit()
        self.pwd1.setEchoMode(QLineEdit.Password)
        self.pwd1.setPlaceholderText("En az 6 karakter kişisel şifre...")
        form.addRow("Kişisel Şifre:", self.pwd1)

        self.pwd2 = QLineEdit()
        self.pwd2.setEchoMode(QLineEdit.Password)
        self.pwd2.setPlaceholderText("Kişisel şifre (tekrar)...")
        form.addRow("Şifre Tekrar:", self.pwd2)
        lay.addLayout(form)

        btns = QHBoxLayout()
        btns.addStretch()
        cancel_b = QPushButton("İptal")
        cancel_b.clicked.connect(self.reject)
        btns.addWidget(cancel_b)

        ok_b = QPushButton("Anahtar Çifti Üret && Kaydet")
        ok_b.setObjectName("primaryBtn")
        ok_b.clicked.connect(self._create)
        btns.addWidget(ok_b)
        lay.addLayout(btns)

    def _create(self):
        root = self.drive_combo.currentData()
        if not root:
            QMessageBox.warning(self, "USB Gerekli", "Lütfen geçerli bir USB flash bellek takın.")
            return
        p1, p2 = self.pwd1.text(), self.pwd2.text()
        if len(p1) < 6 or p1 != p2:
            QMessageBox.warning(self, "Şifre Hatası", "Şifreler eşleşmiyor veya 6 karakterden kısa.")
            return
        res = self.auth_service.provision_usb_key(root, p1, operator_name=self.op_input.text().strip() or "Adli Bilişim Uzmanı")
        QMessageBox.information(
            self,
            "USB Anahtarı Hazır",
            f"Ed25519 anahtar çifti oluşturuldu.\nSürücü: {res['label']} ({res['drive_letter']})\nAnahtar ID: {res['key_id']}",
        )
        self.accept()


class UsbLoginDialog(QDialog):
    """Dark Forensic Two-Factor USB Cryptographic Login Screen."""

    def __init__(
        self,
        db_path: str = "data/forensics.db",
        auth_config_path: str = "data/usb_auth.json",
        custom_usb_roots=None,
        auto_poll: bool = True,
        parent=None,
    ):
        super().__init__(parent)
        self.setWindowTitle("FORENSIC CORE • USB Kriptografik Kimlik Doğrulama")
        self.setWindowIcon(get_app_icon())
        self.setMinimumSize(1020, 610)
        self.resize(1060, 640)

        self.auth_service = UsbCryptoAuthService(
            config_path=auth_config_path,
            db_path=db_path,
            custom_usb_roots=custom_usb_roots,
        )
        self._usb_verified = False
        self._verified_usb_info: Dict[str, Any] = {}
        self.auth_result: Optional[Dict[str, Any]] = None

        self._apply_styles()
        self._build_ui()
        self.check_usb_now()

        self._poll_timer = QTimer(self)
        self._poll_timer.setInterval(1200)
        self._poll_timer.timeout.connect(self._on_poll_tick)
        if auto_poll:
            self._poll_timer.start()

    def _apply_styles(self) -> None:
        self.setStyleSheet("""
            QDialog { background-color: #080D13; color: #E5E7EB; font-family: 'Segoe UI', Arial; }
            QFrame#leftPanel {
                background-color: #0D1520;
                border-right: 1px solid #1E293B;
            }
            QFrame#rightPanel { background-color: #080D13; }
            QFrame#infoTile {
                background-color: #111B28;
                border: 1px solid #1E293B;
                border-radius: 8px;
            }
            QFrame#pwdCard {
                background-color: #0E1621;
                border: 1px solid #1E293B;
                border-radius: 10px;
            }
            QFrame#footerBar {
                background-color: #060A0F;
                border-top: 1px solid #1E293B;
            }
            QLabel#brandTitle { font-size: 21px; font-weight: 800; letter-spacing: 2px; color: #F8FAFC; }
            QLabel#brandSub { font-size: 11px; font-weight: 600; letter-spacing: 1.5px; color: #38BDF8; }
            QLabel#onlineBadge {
                background-color: rgba(16, 185, 129, 0.14);
                color: #34D399;
                border: 1px solid rgba(16, 185, 129, 0.4);
                border-radius: 11px;
                padding: 4px 12px;
                font-size: 11px;
                font-weight: 700;
            }
            QLabel#tileKey { font-size: 10px; font-weight: 700; letter-spacing: 1px; color: #64748B; }
            QLabel#tileVal { font-size: 13px; font-weight: 700; color: #F1F5F9; font-family: Consolas; }
            QLabel#stateHeadline { font-size: 17px; font-weight: 800; letter-spacing: 1px; color: #38BDF8; }
            QLabel#stateSub { font-size: 12px; color: #94A3B8; }
            QLineEdit#pwdInput {
                background-color: #0B1117;
                color: #F8FAFC;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 11px 14px;
                font-size: 14px;
                letter-spacing: 2px;
            }
            QLineEdit#pwdInput:focus { border: 1px solid #38BDF8; }
            QLineEdit#pwdInput:disabled { background-color: #0B1016; color: #475569; border-color: #1E293B; }
            QPushButton#unlockBtn {
                background-color: #0284C7;
                color: #FFFFFF;
                border: 1px solid #38BDF8;
                border-radius: 8px;
                padding: 12px 18px;
                font-size: 13px;
                font-weight: 800;
                letter-spacing: 1px;
            }
            QPushButton#unlockBtn:hover { background-color: #0369A1; }
            QPushButton#unlockBtn:disabled {
                background-color: #1E293B;
                color: #64748B;
                border-color: #334155;
            }
            QPushButton#ghostBtn {
                background-color: #111B28;
                color: #CBD5E1;
                border: 1px solid #334155;
                border-radius: 8px;
                padding: 8px 12px;
                font-size: 12px;
            }
            QPushButton#ghostBtn:hover { border-color: #38BDF8; color: #FFFFFF; }
        """)

    def _build_ui(self) -> None:
        root_lay = QVBoxLayout(self)
        root_lay.setContentsMargins(0, 0, 0, 0)
        root_lay.setSpacing(0)

        body = QHBoxLayout()
        body.setContentsMargins(0, 0, 0, 0)
        body.setSpacing(0)

        # ---------------- LEFT PANEL ----------------
        left = QFrame()
        left.setObjectName("leftPanel")
        left.setFixedWidth(340)
        l_lay = QVBoxLayout(left)
        l_lay.setContentsMargins(28, 30, 28, 24)
        l_lay.setSpacing(14)

        logo_row = QHBoxLayout()
        logo_lbl = QLabel()
        pix = get_brand_pixmap(62)
        if not pix.isNull():
            logo_lbl.setPixmap(pix)
        logo_row.addWidget(logo_lbl)
        title_col = QVBoxLayout()
        title_col.setSpacing(2)
        lbl_title = QLabel("FORENSIC CORE")
        lbl_title.setObjectName("brandTitle")
        lbl_sub = QLabel("DIGITAL FORENSICS PLATFORM")
        lbl_sub.setObjectName("brandSub")
        title_col.addWidget(lbl_title)
        title_col.addWidget(lbl_sub)
        logo_row.addLayout(title_col)
        logo_row.addStretch()
        l_lay.addLayout(logo_row)

        sys_row = QHBoxLayout()
        online_lbl = QLabel("● SYSTEM ONLINE")
        online_lbl.setObjectName("onlineBadge")
        sys_row.addWidget(online_lbl)
        sys_row.addStretch()
        l_lay.addLayout(sys_row)

        intro = QLabel(
            "Adli Bilişim İnceleme Sistemi yalnızca kayıtlı fiziksel USB kriptografik güvenlik "
            "anahtarı ve kişisel doğrulama parolası ile açılır."
        )
        intro.setWordWrap(True)
        intro.setStyleSheet("color: #94A3B8; font-size: 12px; line-height: 1.45;")
        l_lay.addWidget(intro)

        for k, v in [
            ("KİMLİK DOĞRULAMA", "USB Ed25519 Challenge-Response"),
            ("İKİNCİ FAKTÖR", "PBKDF2-HMAC-SHA256 (200k)"),
            ("DONANIM DESTEĞİ", "USB Security Key / FIDO2-Ready"),
            ("DENETİM ZİNCİRİ", "SHA-256 Hash-Chained AuditLog"),
        ]:
            card = QFrame()
            card.setObjectName("infoTile")
            c_lay = QVBoxLayout(card)
            c_lay.setContentsMargins(12, 9, 12, 9)
            c_lay.setSpacing(2)
            lk = QLabel(k)
            lk.setObjectName("tileKey")
            lv = QLabel(v)
            lv.setObjectName("tileVal")
            lv.setStyleSheet("font-size: 12px; color: #E2E8F0; font-family: Consolas;")
            c_lay.addWidget(lk)
            c_lay.addWidget(lv)
            l_lay.addWidget(card)

        l_lay.addStretch()
        self.provision_btn = QPushButton("⚙️ İlk USB Anahtarı Kurulumu")
        self.provision_btn.setObjectName("ghostBtn")
        self.provision_btn.clicked.connect(self._open_provision_dialog)
        self.provision_btn.setVisible(not self.auth_service.is_provisioned())
        l_lay.addWidget(self.provision_btn)

        body.addWidget(left)

        # ---------------- RIGHT PANEL ----------------
        right = QFrame()
        right.setObjectName("rightPanel")
        r_lay = QVBoxLayout(right)
        r_lay.setContentsMargins(36, 26, 36, 24)
        r_lay.setSpacing(12)

        top_head = QHBoxLayout()
        h_col = QVBoxLayout()
        h_col.setSpacing(2)
        h_title = QLabel("Güvenlik Anahtarı")
        h_title.setStyleSheet("font-size: 20px; font-weight: 700; color: #F8FAFC;")
        self.lbl_subtitle = QLabel("USB kriptografik kimliğiniz kontrol ediliyor.")
        self.lbl_subtitle.setObjectName("stateSub")
        h_col.addWidget(h_title)
        h_col.addWidget(self.lbl_subtitle)
        top_head.addLayout(h_col)
        top_head.addStretch()

        recheck_btn = QPushButton("🔄 USB Kontrol Et")
        recheck_btn.setObjectName("ghostBtn")
        recheck_btn.clicked.connect(self.check_usb_now)
        top_head.addWidget(recheck_btn)
        r_lay.addLayout(top_head)

        # Animated USB Key
        self.anim_widget = UsbKeyAnimationWidget(self)
        r_lay.addWidget(self.anim_widget)

        self.lbl_state_headline = QLabel("GÜVENLİK ANAHTARI BEKLENİYOR")
        self.lbl_state_headline.setObjectName("stateHeadline")
        self.lbl_state_headline.setAlignment(Qt.AlignCenter)
        r_lay.addWidget(self.lbl_state_headline)

        self.lbl_crypto_trace = QLabel("Takılı USB (Key D:) üzerindeki Ed25519 anahtarı bekleniyor...")
        self.lbl_crypto_trace.setAlignment(Qt.AlignCenter)
        self.lbl_crypto_trace.setStyleSheet("font-family: Consolas; font-size: 11px; color: #64748B;")
        r_lay.addWidget(self.lbl_crypto_trace)

        # Telemetry 3-Tile Strip
        tiles_row = QHBoxLayout()
        tiles_row.setSpacing(10)
        self.tile_usb_val = self._make_telemetry_tile(tiles_row, "USB DEVICE", "BEKLENİYOR")
        self.tile_auth_val = self._make_telemetry_tile(tiles_row, "AUTHENTICATION", "PENDING")
        self.tile_sec_val = self._make_telemetry_tile(tiles_row, "SECURITY LEVEL", "TWO-FACTOR")
        r_lay.addLayout(tiles_row)

        # Step 2: Personal Password Card
        pwd_card = QFrame()
        pwd_card.setObjectName("pwdCard")
        p_lay = QVBoxLayout(pwd_card)
        p_lay.setContentsMargins(16, 14, 16, 14)
        p_lay.setSpacing(8)

        self.lbl_pwd_prompt = QLabel("Kişisel güvenlik şifrenizi girin")
        self.lbl_pwd_prompt.setStyleSheet("font-size: 13px; font-weight: 700; color: #E2E8F0;")
        p_lay.addWidget(self.lbl_pwd_prompt)

        pwd_row = QHBoxLayout()
        self.pwd_input = QLineEdit()
        self.pwd_input.setObjectName("pwdInput")
        self.pwd_input.setEchoMode(QLineEdit.Password)
        self.pwd_input.setPlaceholderText("••••••••••••")
        self.pwd_input.returnPressed.connect(self._on_submit_password)
        pwd_row.addWidget(self.pwd_input, 1)

        self.eye_btn = QPushButton("👁")
        self.eye_btn.setObjectName("ghostBtn")
        self.eye_btn.setFixedWidth(44)
        self.eye_btn.setCheckable(True)
        self.eye_btn.toggled.connect(
            lambda checked: self.pwd_input.setEchoMode(QLineEdit.Normal if checked else QLineEdit.Password)
        )
        pwd_row.addWidget(self.eye_btn)
        p_lay.addLayout(pwd_row)

        self.lbl_error = QLabel("")
        self.lbl_error.setStyleSheet("color: #F87171; font-size: 12px; font-weight: 600;")
        p_lay.addWidget(self.lbl_error)

        self.unlock_btn = QPushButton("GÜVENLİ OTURUMU BAŞLAT")
        self.unlock_btn.setObjectName("unlockBtn")
        self.unlock_btn.clicked.connect(self._on_submit_password)
        p_lay.addWidget(self.unlock_btn)

        r_lay.addWidget(pwd_card)
        body.addWidget(right, 1)
        root_lay.addLayout(body, 1)

        # ---------------- FOOTER ----------------
        footer = QFrame()
        footer.setObjectName("footerBar")
        f_lay = QHBoxLayout(footer)
        f_lay.setContentsMargins(20, 8, 20, 8)
        f_left = QLabel("SECURE AUTHENTICATION v1.0  •  ENCRYPTED SESSION")
        f_left.setStyleSheet("font-family: Consolas; font-size: 11px; color: #64748B;")
        f_right = QLabel("ISO/IEC 27037  •  NIST SP 800-86  •  2FA HARDWARE GATE")
        f_right.setStyleSheet("font-family: Consolas; font-size: 11px; color: #64748B;")
        f_lay.addWidget(f_left)
        f_lay.addStretch()
        f_lay.addWidget(f_right)
        root_lay.addWidget(footer)

    def _make_telemetry_tile(self, parent_layout: QHBoxLayout, key: str, default_val: str) -> QLabel:
        tile = QFrame()
        tile.setObjectName("infoTile")
        t_lay = QVBoxLayout(tile)
        t_lay.setContentsMargins(12, 8, 12, 8)
        t_lay.setSpacing(2)
        lk = QLabel(key)
        lk.setObjectName("tileKey")
        lv = QLabel(default_val)
        lv.setObjectName("tileVal")
        t_lay.addWidget(lk)
        t_lay.addWidget(lv)
        parent_layout.addWidget(tile, 1)
        return lv

    def _on_poll_tick(self) -> None:
        self.check_usb_now()
        rem = self.auth_service.get_lockout_remaining()
        if rem > 0:
            self.lbl_error.setText(f"🔒 Çok fazla hatalı deneme! Kilit süresi: {rem} sn")
            self.unlock_btn.setEnabled(False)
            self.pwd_input.setEnabled(False)
        elif self._usb_verified and not self.pwd_input.isEnabled():
            self.lbl_error.setText("")
            self.pwd_input.setEnabled(True)
            self.unlock_btn.setEnabled(True)

    def check_usb_now(self) -> Dict[str, Any]:
        """Run live USB detection + Ed25519 challenge-response and update UI state."""
        res = self.auth_service.verify_usb_challenge()
        state = res.get("state", "WAITING_USB")
        self.anim_widget.set_auth_state(state)
        self.provision_btn.setVisible(not self.auth_service.is_provisioned())

        if res.get("verified"):
            was_verified = self._usb_verified
            self._usb_verified = True
            self._verified_usb_info = res
            drv_str = f"{res.get('volume_label', 'KEY').upper()} ({res.get('drive_letter', 'D:')})"
            self.lbl_state_headline.setText("DİJİTAL İMZA DOĞRULANDI")
            self.lbl_state_headline.setStyleSheet("font-size: 17px; font-weight: 800; letter-spacing: 1px; color: #34D399;")
            self.lbl_subtitle.setText("1. Doğrulama başarılı — şimdi kişisel güvenlik şifrenizi girin.")
            self.lbl_crypto_trace.setText(
                f"Challenge: {res.get('challenge_hex')}...  |  Ed25519 İmza: {res.get('signature_hex')}...  |  {res.get('capacity_gb', '')}"
            )
            self.tile_usb_val.setText(drv_str)
            self.tile_usb_val.setStyleSheet("font-size: 13px; font-weight: 700; color: #38BDF8; font-family: Consolas;")
            self.tile_auth_val.setText("VERIFIED")
            self.tile_auth_val.setStyleSheet("font-size: 13px; font-weight: 700; color: #34D399; font-family: Consolas;")

            if self.auth_service.get_lockout_remaining() == 0:
                self.pwd_input.setEnabled(True)
                self.unlock_btn.setEnabled(True)
                if not was_verified:
                    self.pwd_input.setFocus()
        else:
            self._usb_verified = False
            self._verified_usb_info = {}
            self.pwd_input.setEnabled(False)
            self.unlock_btn.setEnabled(False)
            if state == "NO_PROVISION":
                self.lbl_state_headline.setText("USB GÜVENLİK ANAHTARI TANIMLANMADI")
                self.lbl_state_headline.setStyleSheet("font-size: 16px; font-weight: 800; color: #FBBF24;")
                self.lbl_subtitle.setText("Sol alttan 'İlk USB Anahtarı Kurulumu' ile USB belleğinizi kaydedin.")
            elif state == "CHALLENGE_FAILED":
                self.lbl_state_headline.setText("KRİPTOGRAFİK İMZA REDDEDİLDİ")
                self.lbl_state_headline.setStyleSheet("font-size: 16px; font-weight: 800; color: #F87171;")
                self.lbl_subtitle.setText(res.get("message", ""))
            elif state == "USB_NO_KEY":
                self.lbl_state_headline.setText("USB ALGILANDI • ANAHTAR BULUNAMADI")
                self.lbl_state_headline.setStyleSheet("font-size: 16px; font-weight: 800; color: #FBBF24;")
                self.lbl_subtitle.setText(res.get("message", ""))
            else:
                self.lbl_state_headline.setText("GÜVENLİK ANAHTARI TAKIN")
                self.lbl_state_headline.setStyleSheet("font-size: 17px; font-weight: 800; letter-spacing: 1px; color: #38BDF8;")
                self.lbl_subtitle.setText("USB anahtarı bekleniyor (Key D:)...")
            self.lbl_crypto_trace.setText(res.get("message", ""))
            self.tile_usb_val.setText(
                f"{res.get('volume_label', '-')} ({res.get('drive_letter', '-')})" if res.get("drive_letter", "-") != "-" else "BEKLENİYOR"
            )
            self.tile_usb_val.setStyleSheet("font-size: 13px; font-weight: 700; color: #94A3B8; font-family: Consolas;")
            self.tile_auth_val.setText("WAITING")
            self.tile_auth_val.setStyleSheet("font-size: 13px; font-weight: 700; color: #FBBF24; font-family: Consolas;")
        return res

    def _on_submit_password(self) -> None:
        # Re-verify USB challenge at submit time so physical removal is caught immediately
        usb_res = self.check_usb_now()
        if not usb_res.get("verified"):
            self.lbl_error.setText("USB güvenlik anahtarı takılı değil veya imza doğrulanamadı.")
            return

        res = self.auth_service.verify_personal_password(self.pwd_input.text(), usb_verified=True)
        if res.get("authenticated"):
            self.auth_result = {**res, "usb": usb_res}
            self._poll_timer.stop()
            self.accept()
            return

        self.pwd_input.clear()
        self.lbl_error.setText(res.get("reason", "Giriş başarısız."))
        if res.get("locked"):
            self.anim_widget.set_auth_state("LOCKED")
            self.pwd_input.setEnabled(False)
            self.unlock_btn.setEnabled(False)

    def _open_provision_dialog(self) -> None:
        dlg = ProvisionUsbDialog(self.auth_service, parent=self)
        if dlg.exec() == QDialog.Accepted:
            self.check_usb_now()
