"""Service-report draft generation, validation, and PDF output.

The local fallback is intentionally deterministic and only organizes supplied
notes. Replace it with a reviewed provider adapter if a real LLM is configured.

Report content is stored as a JSON object of named sections. All user text is
XML-escaped before it reaches ReportLab, because ReportLab paragraphs interpret
markup (including <img> tags that can read local files).
"""
from dataclasses import dataclass
from datetime import datetime
from functools import lru_cache
import io
from html import escape as _html_escape
import json
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    KeepTogether,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)


# Ordered, client-facing report sections: storage key -> heading.
REPORT_SECTIONS: dict[str, str] = {
    "work_performed": "Work performed",
    "findings_observations": "Findings and observations",
    "recommendations": "Recommendations",
    "suggested_follow_up": "Suggested follow-up",
}

# Internal reviewer note; stored with the draft but never printed.
INTERNAL_KEYS = {"source_note"}
ALLOWED_KEYS = set(REPORT_SECTIONS) | INTERNAL_KEYS
MAX_SECTION_LENGTH = 5000

# Draft placeholders. A section still holding one of these was never filled
# in, so it is left out of the client PDF.
NOT_SPECIFIED = "Not separately specified in the supplied notes."
FOLLOW_UP_PLACEHOLDER = (
    "Confirm follow-up needs with the customer if applicable."
)
PLACEHOLDERS = {NOT_SPECIFIED, FOLLOW_UP_PLACEHOLDER}


def make_report_draft(notes: str) -> dict[str, str]:
    """Create a safe no-API fallback; do not infer technical facts."""
    cleaned = notes.strip()
    return {
        "work_performed": cleaned,
        "findings_observations": NOT_SPECIFIED,
        "recommendations": NOT_SPECIFIED,
        "suggested_follow_up": FOLLOW_UP_PLACEHOLDER,
        "source_note": "Draft organized from user-provided notes; verify all details before approval.",
    }


class ReportContentError(ValueError):
    """Raised when edited report content is not a valid section object."""


def validate_report_content(raw: str) -> str:
    """Validate edited content and return it re-serialized.

    Content must be a JSON object whose keys are known section names and
    whose values are strings. Partial objects are allowed.
    """
    try:
        data = json.loads(raw)
    except (TypeError, ValueError):
        raise ReportContentError(
            "Report content must be a JSON object of report sections."
        ) from None

    if not isinstance(data, dict):
        raise ReportContentError(
            "Report content must be a JSON object of report sections."
        )

    unknown = sorted(set(data) - ALLOWED_KEYS)
    if unknown:
        raise ReportContentError(
            "Unknown report section(s): " + ", ".join(unknown)
        )

    cleaned: dict[str, str] = {}
    for key, value in data.items():
        if not isinstance(value, str):
            raise ReportContentError(f"Section {key} must be text.")
        value = value.strip()
        if len(value) > MAX_SECTION_LENGTH:
            raise ReportContentError(
                f"Section {key} must be at most {MAX_SECTION_LENGTH} characters."
            )
        cleaned[key] = value

    return json.dumps(cleaned, ensure_ascii=False)


def report_sections(content: str) -> list[tuple[str, str]]:
    """Return printable (heading, text) pairs in a fixed order.

    Legacy reports saved as plain text are printed as one section.
    """
    try:
        data = json.loads(content)
    except (TypeError, ValueError):
        data = None

    if not isinstance(data, dict):
        text = (content or "").strip()
        return [("Report", text)] if text else []

    sections = []
    for key, heading in REPORT_SECTIONS.items():
        value = data.get(key)
        if not isinstance(value, str):
            continue
        value = value.strip()
        if value and value not in PLACEHOLDERS:
            sections.append((heading, value))
    return sections


# PDF rendering


@dataclass
class ReportContext:
    """Everything printed on a client-facing service report."""

    report_id: int
    job_title: str
    trade_type: str
    customer_name: str
    customer_address: str | None
    customer_phone: str | None
    customer_email: str | None
    prepared_by: str
    service_date: datetime
    approved_at: datetime
    content: str
    original_notes: str


FONT_DIR = Path(__file__).parent / "fonts"


@lru_cache(maxsize=1)
def _fonts() -> tuple[str, str]:
    """Register an embedded Unicode font; fall back to Helvetica."""
    regular = FONT_DIR / "DejaVuSans.ttf"
    bold = FONT_DIR / "DejaVuSans-Bold.ttf"
    try:
        pdfmetrics.registerFont(TTFont("TradeDeskSans", str(regular)))
        pdfmetrics.registerFont(TTFont("TradeDeskSans-Bold", str(bold)))
        return "TradeDeskSans", "TradeDeskSans-Bold"
    except Exception:
        return "Helvetica", "Helvetica-Bold"


def _supported(text: str, font_name: str) -> str:
    """Replace characters the font cannot draw so they don't print as boxes."""
    if font_name.startswith("Helvetica"):
        return text.encode("latin-1", "replace").decode("latin-1")
    face = pdfmetrics.getFont(font_name).face
    cmap = face.charToGlyph
    return "".join(
        ch if ch in "\n\t" or ord(ch) in cmap else "?"
        for ch in text
    )


def _para(text: str, style: ParagraphStyle) -> Paragraph:
    """Escape user text for ReportLab markup and keep line breaks."""
    safe = _html_escape(_supported(text, style.fontName), quote=False)
    return Paragraph(safe.replace("\n", "<br/>"), style)


def _date(value: datetime) -> str:
    return f"{value:%B} {value.day}, {value.year}"


def create_pdf(ctx: ReportContext) -> bytes:
    """Render an approved report as a client-ready PDF."""
    regular, bold = _fonts()

    base = ParagraphStyle(
        "Body", fontName=regular, fontSize=10, leading=14,
        splitLongWords=True,
    )
    small = ParagraphStyle("Small", parent=base, fontSize=8.5, leading=11,
                           textColor=colors.HexColor("#5b6570"))
    label = ParagraphStyle("Label", parent=small, fontName=bold)
    title = ParagraphStyle("Title", parent=base, fontName=bold, fontSize=18,
                           leading=22, textColor=colors.HexColor("#102a43"))
    heading = ParagraphStyle("Heading", parent=base, fontName=bold,
                             fontSize=12, leading=16, spaceBefore=10,
                             spaceAfter=4, textColor=colors.HexColor("#102a43"))
    right = ParagraphStyle("Right", parent=small, alignment=TA_RIGHT)

    # Usable width inside the page frame (frames add 6pt padding per side).
    avail = letter[0] - 1.5 * inch - 12

    story = []

    header = Table(
        [[
            _para("Service Report", title),
            _para(
                f"Report #{ctx.report_id}\n"
                f"Service date: {_date(ctx.service_date)}\n"
                f"Approved: {_date(ctx.approved_at)}",
                right,
            ),
        ]],
        colWidths=[avail * 0.6, avail * 0.4],
    )
    header.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("LINEBELOW", (0, 0), (-1, 0), 1.2, colors.HexColor("#102a43")),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
    ]))
    story += [header, Spacer(1, 12)]

    customer_lines = [ctx.customer_name]
    customer_lines += [
        value for value in (
            ctx.customer_address, ctx.customer_phone, ctx.customer_email
        ) if value
    ]
    details = Table(
        [
            [_para("CUSTOMER", label), _para("JOB", label)],
            [
                _para("\n".join(customer_lines), base),
                _para(
                    f"{ctx.job_title}\nTrade: {ctx.trade_type}\n"
                    f"Prepared by: {ctx.prepared_by}",
                    base,
                ),
            ],
        ],
        colWidths=[avail / 2, avail / 2],
    )
    details.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#f3f6f8")),
        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#d7dde3")),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story += [details, Spacer(1, 6)]

    sections = report_sections(ctx.content)
    if not sections:
        sections = [("Work performed", ctx.original_notes)]
    for section_heading, text in sections:
        story.append(_para(section_heading, heading))
        story.append(_para(text, base))

    # Separate signature and date lines with gaps between them.
    gap = 0.2 * inch
    line_widths = [
        (avail - 3 * gap) * share for share in (0.34, 0.16, 0.34, 0.16)
    ]
    signature = Table(
        [
            ["", "", "", "", "", "", ""],
            [
                _para("Technician signature", small), "",
                _para("Date", small), "",
                _para("Customer signature", small), "",
                _para("Date", small),
            ],
        ],
        colWidths=[
            line_widths[0], gap, line_widths[1], gap,
            line_widths[2], gap, line_widths[3],
        ],
        rowHeights=[28, None],
    )
    signature.setStyle(TableStyle(
        [
            ("LINEBELOW", (col, 0), (col, 0), 0.6, colors.black)
            for col in (0, 2, 4, 6)
        ]
        + [
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ]
    ))
    story += [Spacer(1, 24), KeepTogether([signature])]

    def footer(canvas, doc):
        canvas.saveState()
        canvas.setFont(regular, 8)
        canvas.setFillColor(colors.HexColor("#5b6570"))
        canvas.drawString(
            doc.leftMargin + 6, 0.5 * inch,
            f"Report #{ctx.report_id} · Generated by TradeDesk",
        )
        canvas.drawRightString(
            letter[0] - doc.rightMargin - 6, 0.5 * inch, f"Page {doc.page}"
        )
        canvas.restoreState()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=letter,
        leftMargin=0.75 * inch,
        rightMargin=0.75 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.8 * inch,
        title=f"Service Report #{ctx.report_id}",
        author="TradeDesk",
    )
    doc.build(story, onFirstPage=footer, onLaterPages=footer)
    return buffer.getvalue()
