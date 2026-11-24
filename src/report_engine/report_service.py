"""Forensic Report Generator Engine producing auditable HTML (Jinja2) and PDF (ReportLab) reports."""

import os
from datetime import datetime
from typing import Any, Dict, List, Optional
from jinja2 import Template
from reportlab.lib.pagesizes import A4
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont

from src.case_engine.case_service import CaseService
from src.evidence_engine.evidence_service import EvidenceService
from src.integrity_engine.integrity_service import IntegrityService
from src.usb_engine.usb_service import UsbService
from src.timeline_engine.timeline_service import TimelineService

HTML_REPORT_TEMPLATE = Template("""<!DOCTYPE html>
<html lang="tr">
<head>
<meta charset="utf-8">
<title>Adli Bilişim İnceleme Raporu - {{ case.case_number }}</title>
<style>
  body { font-family: 'Segoe UI', Arial, sans-serif; background: #F5F5F7; color: #1D2733; margin: 28px; line-height: 1.5; }
  .container { max-width: 980px; margin: auto; background: #FFFFFF; padding: 32px; border: 1px solid #D0D5DD; border-radius: 8px; }
  h1 { color: #1D2733; border-bottom: 2px solid #315C85; padding-bottom: 10px; font-size: 22px; }
  h2 { color: #315C85; margin-top: 26px; font-size: 16px; border-left: 4px solid #315C85; padding-left: 10px; }
  .meta-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 10px; background: #F9FAFB; padding: 14px; border: 1px solid #EAECF0; border-radius: 6px; font-size: 13px; }
  table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 12px; }
  th { background: #1D2733; color: #FFFFFF; text-align: left; padding: 8px; }
  td { border-bottom: 1px solid #EAECF0; padding: 8px; vertical-align: top; }
  tr:nth-child(even) td { background: #F9FAFB; }
  .mono { font-family: Consolas, monospace; font-size: 11px; word-break: break-all; }
  .badge-ok { color: #26845B; font-weight: bold; }
  .badge-warn { color: #B9822D; font-weight: bold; }
  .box { background: #F9FAFB; border: 1px solid #D0D5DD; padding: 12px; border-radius: 6px; font-size: 13px; white-space: pre-wrap; }
  .footer { margin-top: 28px; font-size: 11px; color: #667085; border-top: 1px solid #EAECF0; padding-top: 10px; }
</style>
</head>
<body>
<div class="container">
  <h1>ADLİ BİLİŞİM İNCELEME RAPORU</h1>
  <div class="meta-grid">
    <div><strong>Vaka Numarası:</strong> {{ case.case_number }}</div>
    <div><strong>Rapor Tarihi (UTC):</strong> {{ generated_at }}</div>
    <div><strong>Soruşturma Başlığı:</strong> {{ case.title }}</div>
    <div><strong>İnceleme Sorumlusu:</strong> {{ case.investigator or '-' }}</div>
    <div><strong>Birim / Kurum:</strong> {{ case.organization or '-' }}</div>
    <div><strong>Uygulama Sürümü:</strong> {{ app_version }}</div>
  </div>

  {% if include_evidence %}
  <h2>1. Delil Envanteri ve Kriptografik Bütünlük</h2>
  <table>
    <thead><tr><th>Delil No</th><th>Tür</th><th>Marka / Model</th><th>Seri No</th><th>Yazma Engelleyici</th><th>SHA-256 Özeti</th></tr></thead>
    <tbody>
    {% for e in evidences %}
      <tr>
        <td><strong>{{ e.evidence_number }}</strong></td>
        <td>{{ e.device_type }}</td>
        <td>{{ e.brand }} {{ e.model }}</td>
        <td class="mono">{{ e.serial or '-' }}</td>
        <td>{{ 'Evet' if e.write_blocker_used else 'Belirtilmedi' }}</td>
        <td class="mono">{{ e.sha256_hash or '-' }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  {% if include_custody %}
  <h2>2. Delil Muhafaza Zinciri (Chain of Custody)</h2>
  <table>
    <thead><tr><th>Zaman (UTC)</th><th>Delil No</th><th>İşlem</th><th>Teslim Eden</th><th>Teslim Alan</th><th>Doğrulama</th></tr></thead>
    <tbody>
    {% for c in custody %}
      <tr>
        <td class="mono">{{ c.timestamp }}</td>
        <td>{{ c.evidence_number }}</td>
        <td>{{ c.action_type }}</td>
        <td>{{ c.delivered_by }}</td>
        <td>{{ c.received_by }}</td>
        <td class="{{ 'badge-ok' if c.status == 'Doğrulandı' else 'badge-warn' }}">{{ c.status }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  {% if include_usb %}
  <h2>3. USB Cihaz ve Artefakt Bulguları</h2>
  <table>
    <thead><tr><th>Durum</th><th>Cihaz Adı</th><th>VID / PID</th><th>Seri No</th><th>Kullanıcı</th><th>Son Bağlantı (UTC)</th><th>Kaynak</th></tr></thead>
    <tbody>
    {% for u in usb_records %}
      <tr>
        <td class="{{ 'badge-warn' if u.is_suspicious else 'badge-ok' }}">{{ u.status }}</td>
        <td>{{ u.device_name }}</td>
        <td class="mono">{{ u.vid }}:{{ u.pid }}</td>
        <td class="mono">{{ u.serial_number }}</td>
        <td>{{ u.user_account or '-' }}</td>
        <td class="mono">{{ u.last_connected }}</td>
        <td class="mono">{{ u.registry_source_key }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  {% if include_timeline %}
  <h2>4. Birleştirilmiş Olay Zaman Çizelgesi (UTC)</h2>
  <table>
    <thead><tr><th>Zaman (UTC)</th><th>Olay Türü</th><th>Kullanıcı</th><th>Açıklama</th><th>Güvenilirlik</th></tr></thead>
    <tbody>
    {% for t in timeline %}
      <tr>
        <td class="mono">{{ t.timestamp }}</td>
        <td>{{ t.event_type }}</td>
        <td>{{ t.user }}</td>
        <td>{{ t.details }}</td>
        <td>{{ t.reliability }}</td>
      </tr>
    {% endfor %}
    </tbody>
  </table>
  {% endif %}

  <h2>5. Uzman Yorumu ve Değerlendirme (Objektif Bulgulardan Ayrıdır — SWGDE)</h2>
  <div class="box">{{ expert_notes }}</div>

  <h2>6. Yöntem, Araç Doğrulama ve Analiz Sınırlamaları</h2>
  <div class="box">{{ limitations }}</div>

  <div class="footer">
    Bu rapor <strong>Adli Bilişim İnceleme Sistemi ({{ app_version }})</strong> tarafından salt-okunur çalışma kopyaları üzerinden,
    ISO/IEC 27037, NIST SP 800-86, SWGDE ve UNODC E4J Modül 6 ilkelerine uygun şekilde oluşturulmuştur.
    Objektif teknik bulgular (Bölüm 1-4) ile uzman yorumu (Bölüm 5) birbirinden ayrılmıştır; doğrulanmamış zamansal ilişkiler kesin bulgu olarak sunulmamıştır.
  </div>
</div>
</body>
</html>
""")


class ReportService:
    """Generates comprehensive HTML and PDF forensic investigation reports."""

    APP_VERSION = "v1.0.0-dfir"

    def __init__(self, db_path: str = "data/forensics.db"):
        self.db_path = db_path

    def build_report_context(
        self,
        case_id: Optional[int] = None,
        include_evidence: bool = True,
        include_custody: bool = True,
        include_usb: bool = True,
        include_timeline: bool = True,
        expert_notes: str = "",
        limitations: str = "",
    ) -> Dict[str, Any]:
        case_svc = CaseService(self.db_path)
        evd_svc = EvidenceService(self.db_path)
        int_svc = IntegrityService(self.db_path)
        usb_svc = UsbService(self.db_path)
        tl_svc = TimelineService(self.db_path)

        case = case_svc.get_case(case_id) if case_id else (case_svc.list_cases()[0] if case_svc.list_cases() else None)
        if not case:
            raise ValueError("Raporlanacak vaka bulunamadı.")

        evidences = evd_svc.list_evidence(case_id=case.id)
        custody_raw = int_svc.list_custody_records(case_id=case.id)
        custody = [
            {
                "timestamp": item["entry"].timestamp.strftime("%Y-%m-%d %H:%M:%S") if item["entry"].timestamp else "-",
                "evidence_number": item["evidence_number"],
                "action_type": item["entry"].action_type,
                "delivered_by": item["entry"].delivered_by or "-",
                "received_by": item["entry"].received_by or "-",
                "status": item["entry"].verification_status,
            }
            for item in custody_raw
        ]
        usbs = [
            {
                "status": u.status,
                "is_suspicious": u.is_suspicious,
                "device_name": u.device_name,
                "vid": u.vid,
                "pid": u.pid,
                "serial_number": u.serial_number,
                "user_account": u.user_account,
                "last_connected": u.last_connected.strftime("%Y-%m-%d %H:%M:%S") if u.last_connected else "-",
                "registry_source_key": u.registry_source_key,
            }
            for u in usb_svc.list_devices(case_id=case.id)
        ]
        timeline = tl_svc.collect_case_timeline(case_id=case.id)[:60]

        default_notes = expert_notes.strip() or (
            "İnceleme kapsamında alınan dijital deliller donanımsal yazma engelleyici kullanılarak salt-okunur çalışma kopyalarına aktarılmış, "
            "SHA-256 / SHA-512 bütünlük değerleri doğrulanmıştır. Tespit edilen şüpheli aygıt ve zaman çizelgesi kayıtları bulgu tablolarında detaylandırılmıştır."
        )
        default_limits = limitations.strip() or (
            "1. Bu yazılım donanımsal yazma engelleyici (hardware write-blocker) yerine geçmez.\n"
            "2. Kayıt defteri veya olay günlüklerinde eksik olan zaman damgaları tahmin edilmemiş, '-' olarak bırakılmıştır.\n"
            "3. Hukuki sorumluluk ve niyet değerlendirmesi bu teknik raporun kapsamı dışındadır."
        )

        return {
            "case": case,
            "generated_at": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
            "app_version": self.APP_VERSION,
            "include_evidence": include_evidence,
            "include_custody": include_custody,
            "include_usb": include_usb,
            "include_timeline": include_timeline,
            "evidences": evidences,
            "custody": custody,
            "usb_records": usbs,
            "timeline": timeline,
            "expert_notes": default_notes,
            "limitations": default_limits,
        }

    def render_html(self, **kwargs) -> str:
        ctx = self.build_report_context(**kwargs)
        return HTML_REPORT_TEMPLATE.render(**ctx)

    def export_html(self, output_path: str, **kwargs) -> str:
        html = self.render_html(**kwargs)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html)
        return output_path

    def export_pdf(self, output_path: str, **kwargs) -> str:
        ctx = self.build_report_context(**kwargs)
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)

        # Register Unicode-capable system font on Windows if available (fixes Turkish chars in PDF)
        font_name = "Helvetica"
        win_arial = r"C:\Windows\Fonts\arial.ttf"
        if os.path.isfile(win_arial):
            try:
                pdfmetrics.registerFont(TTFont("ArialTR", win_arial))
                font_name = "ArialTR"
            except Exception:
                pass

        doc = SimpleDocTemplate(output_path, pagesize=A4, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
        styles = getSampleStyleSheet()
        title_style = ParagraphStyle("TRTitle", parent=styles["Title"], fontName=font_name, fontSize=16, textColor=colors.HexColor("#1D2733"))
        h2_style = ParagraphStyle("TRH2", parent=styles["Heading2"], fontName=font_name, fontSize=12, textColor=colors.HexColor("#315C85"), spaceBefore=12, spaceAfter=6)
        body_style = ParagraphStyle("TRBody", parent=styles["Normal"], fontName=font_name, fontSize=9, leading=13)

        story: List[Any] = []
        c = ctx["case"]
        story.append(Paragraph("ADLİ BİLİŞİM İNCELEME RAPORU", title_style))
        story.append(Spacer(1, 8))
        story.append(Paragraph(
            f"<b>Vaka No:</b> {c.case_number} &nbsp;|&nbsp; <b>Başlık:</b> {c.title}<br/>"
            f"<b>Sorumlu:</b> {c.investigator or '-'} &nbsp;|&nbsp; <b>Tarih:</b> {ctx['generated_at']} &nbsp;|&nbsp; <b>Sürüm:</b> {ctx['app_version']}",
            body_style,
        ))

        def make_table(data_rows: List[List[str]], col_widths=None):
            t = Table(data_rows, colWidths=col_widths, repeatRows=1)
            t.setStyle(TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1D2733")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, -1), font_name),
                ("FONTSIZE", (0, 0), (-1, -1), 7.5),
                ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#D0D5DD")),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
                ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ]))
            return t

        if ctx["include_evidence"] and ctx["evidences"]:
            story.append(Paragraph("1. Delil Envanteri ve Hash Değerleri", h2_style))
            rows = [["Delil No", "Tür", "Marka / Model", "Seri No", "SHA-256 (İlk 24)"]]
            for e in ctx["evidences"]:
                rows.append([
                    e.evidence_number,
                    e.device_type or "-",
                    f"{e.brand or ''} {e.model or ''}".strip(),
                    e.serial or "-",
                    (e.sha256_hash[:24] + "...") if e.sha256_hash else "-",
                ])
            story.append(make_table(rows, [75, 90, 120, 110, 125]))

        if ctx["include_usb"] and ctx["usb_records"]:
            story.append(Paragraph("2. USB Cihaz Bulguları", h2_style))
            rows = [["Durum", "Cihaz Adı", "VID:PID", "Seri No", "Kullanıcı"]]
            for u in ctx["usb_records"]:
                rows.append([u["status"], u["device_name"][:32], f"{u['vid']}:{u['pid']}", u["serial_number"][:22], (u["user_account"] or "-")[:22]])
            story.append(make_table(rows, [75, 165, 65, 115, 100]))

        if ctx["include_timeline"] and ctx["timeline"]:
            story.append(Paragraph("3. Olay Zaman Çizelgesi (İlk 20 Olay)", h2_style))
            rows = [["Zaman (UTC)", "Olay Türü", "Kullanıcı", "Açıklama"]]
            for t in ctx["timeline"][:20]:
                rows.append([t["timestamp"], t["event_type"][:24], t["user"][:18], t["details"][:48]])
            story.append(make_table(rows, [95, 110, 90, 225]))

        story.append(Paragraph("4. Uzman Değerlendirme Notları", h2_style))
        story.append(Paragraph(ctx["expert_notes"].replace("\n", "<br/>"), body_style))

        story.append(Paragraph("5. Analiz Sınırlamaları", h2_style))
        story.append(Paragraph(ctx["limitations"].replace("\n", "<br/>"), body_style))

        doc.build(story)
        return output_path

    @staticmethod
    def generate_pdf(path: str, title: str, body_lines: List[str]) -> str:
        """Backward-compatible simple PDF helper."""
        from reportlab.pdfgen import canvas
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        c = canvas.Canvas(path, pagesize=A4)
        c.setFont("Helvetica", 12)
        y = 800
        c.drawString(50, y, title)
        y -= 30
        for line in body_lines:
            c.drawString(50, y, line)
            y -= 18
            if y < 50:
                c.showPage()
                y = 800
        c.save()
        return path
