from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
import os

class ReportService:
    @staticmethod
    def generate_pdf(path, title, body_lines):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        c = canvas.Canvas(path, pagesize=A4)
        c.setFont("Helvetica", 12)
        y = 800
        c.drawString(50, y, title); y -= 30
        for line in body_lines:
            c.drawString(50, y, line); y -= 18
            if y < 50:
                c.showPage(); y = 800
        c.save()
        return path
