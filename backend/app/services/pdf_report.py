"""Generate a PDF security report from scan results."""

import io
from datetime import datetime, timezone

from fpdf import FPDF

from app.models.scan import ScanRecord

RISK_COLORS = {
    "critical": (220, 38, 38),
    "high": (234, 88, 12),
    "medium": (217, 119, 6),
    "low": (37, 99, 235),
    "info": (107, 114, 128),
}

RISK_BG_COLORS = {
    "critical": (254, 242, 242),
    "high": (255, 247, 237),
    "medium": (255, 251, 235),
    "low": (239, 246, 255),
    "info": (249, 250, 251),
}


class SecurityReportPDF(FPDF):
    def __init__(self, target_url: str):
        super().__init__()
        self.target_url = target_url
        self.set_auto_page_break(auto=True, margin=20)

    def header(self):
        self.set_font("Helvetica", "B", 10)
        self.set_text_color(80, 80, 80)
        self.cell(0, 8, "QA Security Scanner Report", new_x="LMARGIN", new_y="NEXT")
        self.set_draw_color(200, 200, 200)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "", 8)
        self.set_text_color(150, 150, 150)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}}", align="C")


def generate_pdf(record: ScanRecord) -> bytes:
    pdf = SecurityReportPDF(record.target_url)
    pdf.alias_nb_pages()
    pdf.add_page()

    # Title
    pdf.set_font("Helvetica", "B", 20)
    pdf.set_text_color(17, 24, 39)
    pdf.cell(0, 12, "Security Scan Report", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # Target URL and date
    pdf.set_font("Helvetica", "", 11)
    pdf.set_text_color(107, 114, 128)
    pdf.cell(0, 7, f"Target: {record.target_url}", new_x="LMARGIN", new_y="NEXT")
    pdf.cell(
        0, 7,
        f"Date: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
        new_x="LMARGIN", new_y="NEXT",
    )
    pdf.ln(6)

    # Summary
    summary = _build_summary(record)
    _draw_summary(pdf, summary)
    pdf.ln(8)

    # Issues by risk level
    risk_order = ["critical", "high", "medium", "low", "info"]
    sorted_issues = sorted(
        record.issues,
        key=lambda i: risk_order.index(i.risk.value) if i.risk.value in risk_order else 99,
    )

    grouped: dict[str, list] = {}
    for issue in sorted_issues:
        risk = issue.risk.value
        grouped.setdefault(risk, []).append(issue)

    if not sorted_issues:
        pdf.set_font("Helvetica", "B", 13)
        pdf.set_text_color(22, 163, 74)
        pdf.cell(0, 12, "No security issues found. The site looks good!", new_x="LMARGIN", new_y="NEXT")
    else:
        for risk in risk_order:
            items = grouped.get(risk, [])
            if not items:
                continue
            _draw_risk_group(pdf, risk, items)

    buf = io.BytesIO()
    pdf.output(buf)
    return buf.getvalue()


def _build_summary(record: ScanRecord) -> dict[str, int]:
    summary = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for issue in record.issues:
        risk = issue.risk.value
        if risk in summary:
            summary[risk] += 1
    return summary


def _draw_summary(pdf: FPDF, summary: dict[str, int]):
    pdf.set_font("Helvetica", "B", 13)
    pdf.set_text_color(17, 24, 39)
    pdf.cell(0, 10, "Summary", new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    col_width = 36
    labels = ["Critical", "High", "Medium", "Low", "Info"]
    keys = ["critical", "high", "medium", "low", "info"]

    x_start = pdf.get_x()
    y_start = pdf.get_y()

    for i, (label, key) in enumerate(zip(labels, keys)):
        x = x_start + i * (col_width + 4)
        bg = RISK_BG_COLORS.get(key, (245, 245, 245))
        color = RISK_COLORS.get(key, (100, 100, 100))

        # Card background
        pdf.set_fill_color(*bg)
        pdf.rect(x, y_start, col_width, 28, style="F")

        # Count
        pdf.set_xy(x, y_start + 3)
        pdf.set_font("Helvetica", "B", 18)
        pdf.set_text_color(*color)
        pdf.cell(col_width, 10, str(summary[key]), align="C")

        # Label
        pdf.set_xy(x, y_start + 15)
        pdf.set_font("Helvetica", "", 8)
        pdf.set_text_color(107, 114, 128)
        pdf.cell(col_width, 8, label, align="C")

    pdf.set_y(y_start + 34)


def _draw_risk_group(pdf: FPDF, risk: str, items: list):
    color = RISK_COLORS.get(risk, (100, 100, 100))

    # Group header
    pdf.set_font("Helvetica", "B", 12)
    pdf.set_text_color(*color)
    label = f"{risk.capitalize()} ({len(items)})"
    pdf.cell(0, 10, label, new_x="LMARGIN", new_y="NEXT")

    pdf.set_draw_color(*color)
    pdf.line(10, pdf.get_y(), 200, pdf.get_y())
    pdf.ln(4)

    for issue in items:
        _draw_issue(pdf, issue, risk)

    pdf.ln(4)


def _draw_issue(pdf: FPDF, issue, risk: str):
    y_before = pdf.get_y()

    # Check if we need a new page (at least 50mm needed for an issue)
    if y_before > 240:
        pdf.add_page()

    bg = RISK_BG_COLORS.get(risk, (245, 245, 245))
    color = RISK_COLORS.get(risk, (100, 100, 100))

    # Issue name
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(17, 24, 39)

    # Risk + type badges inline
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_fill_color(*bg)
    pdf.set_text_color(*color)
    pdf.cell(
        pdf.get_string_width(risk.upper()) + 6, 5,
        risk.upper(), fill=True, new_x="END",
    )
    pdf.cell(3, 5, "")
    pdf.set_fill_color(240, 240, 240)
    pdf.set_text_color(107, 114, 128)
    pdf.cell(
        pdf.get_string_width(issue.type.value.upper()) + 6, 5,
        issue.type.value.upper(), fill=True, new_x="LMARGIN", new_y="NEXT",
    )
    pdf.ln(2)

    # Name
    pdf.set_font("Helvetica", "B", 10)
    pdf.set_text_color(17, 24, 39)
    pdf.multi_cell(0, 6, issue.name, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(1)

    # Message
    pdf.set_font("Helvetica", "", 9)
    pdf.set_text_color(55, 65, 81)
    pdf.multi_cell(0, 5, issue.message, new_x="LMARGIN", new_y="NEXT")
    pdf.ln(2)

    # Recommendation
    pdf.set_fill_color(240, 253, 244)
    rec_y = pdf.get_y()
    pdf.set_x(12)
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(22, 163, 74)
    pdf.cell(0, 5, "RECOMMENDATION", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(12)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(55, 65, 81)
    pdf.multi_cell(186, 5, issue.recommendation, new_x="LMARGIN", new_y="NEXT")
    rec_end_y = pdf.get_y() + 2
    pdf.rect(10, rec_y - 2, 190, rec_end_y - rec_y + 2, style="F")

    # Re-draw text on top of the background (fpdf2 draws in order)
    pdf.set_y(rec_y)
    pdf.set_x(12)
    pdf.set_font("Helvetica", "B", 7)
    pdf.set_text_color(22, 163, 74)
    pdf.cell(0, 5, "RECOMMENDATION", new_x="LMARGIN", new_y="NEXT")
    pdf.set_x(12)
    pdf.set_font("Helvetica", "", 8.5)
    pdf.set_text_color(55, 65, 81)
    pdf.multi_cell(186, 5, issue.recommendation, new_x="LMARGIN", new_y="NEXT")

    pdf.ln(6)
