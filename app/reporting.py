"""Service-report draft generation and PDF output.

The local fallback is intentionally deterministic and only organizes supplied
notes. Replace it with a reviewed provider adapter if a real LLM is configured.
"""
import io
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas


def make_report_draft(notes: str) -> dict[str, str]:
    """Create a safe no-API fallback; do not infer technical facts."""
    cleaned = notes.strip()
    return {
        "work_performed": cleaned,
        "findings_observations": "Not separately specified in the supplied notes.",
        "recommendations": "Not separately specified in the supplied notes.",
        "suggested_follow_up": "Confirm follow-up needs with the customer if applicable.",
        "source_note": "Draft organized from user-provided notes; verify all details before approval.",
    }


def create_pdf(title: str, report_content: str, original_notes: str) -> bytes:
    """Create a readable PDF. Report content is drawn as text, not interpreted as markup."""
    buffer = io.BytesIO()
    pdf = canvas.Canvas(buffer, pagesize=letter)
    page_width, page_height = letter
    left = 54
    y = page_height - 60
    pdf.setTitle("TradeDesk Approved Service Report")
    pdf.setFont("Helvetica-Bold", 16)
    pdf.drawString(left, y, "TradeDesk — Service Report")
    y -= 28
    pdf.setFont("Helvetica-Bold", 11)
    pdf.drawString(left, y, f"Job: {title[:100]}")
    y -= 25
    pdf.setFont("Helvetica-Bold", 10)
    pdf.drawString(left, y, "Approved report content")
    y -= 16
    pdf.setFont("Helvetica", 9)

    # Simple wrapping avoids drawing long user input outside the page.
    for section in (report_content, f"Original notes: {original_notes}"):
        for paragraph in section.splitlines() or [""]:
            words = paragraph.split()
            line = ""
            for word in words:
                candidate = f"{line} {word}".strip()
                if pdf.stringWidth(candidate, "Helvetica", 9) > page_width - 2 * left:
                    pdf.drawString(left, y, line[:250])
                    y -= 13
                    line = word
                else:
                    line = candidate
                if y < 60:
                    pdf.showPage()
                    pdf.setFont("Helvetica", 9)
                    y = page_height - 60
            if line:
                pdf.drawString(left, y, line[:250])
                y -= 15
            y -= 5
    pdf.save()
    return buffer.getvalue()
