"""
Automated Forensic Report Generator
====================================
PDF reports in plain language for technical and non-technical readers.
Requires: reportlab
"""

from datetime import datetime
from pathlib import Path
from typing import Any, List, Optional, Union
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle

NAVY       = colors.HexColor("#1a365d")
NAVY_LIGHT = colors.HexColor("#2c5282")
STROKE     = colors.HexColor("#cbd5e0")
ROW_ALT    = colors.HexColor("#f7fafc")
WHITE      = colors.white


def _parse_report_time(report_generated_at):
    if report_generated_at is None:
        return datetime.now()
    if isinstance(report_generated_at, datetime):
        return report_generated_at
    s = str(report_generated_at).strip()
    try:
        if s.endswith("Z"):
            s = s[:-1]
        return datetime.fromisoformat(s)
    except ValueError:
        pass
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(s[:19], fmt)
        except ValueError:
            continue
    return datetime.now()


def _friendly_date(ts) -> str:
    if not ts or str(ts).upper() == "N/A":
        return "—"
    s = str(ts).strip()
    if "T" in s and len(s) >= 19:
        s = s[:19].replace("T", " ")
    try:
        dt = datetime.strptime(s[:19], "%Y-%m-%d %H:%M:%S")
        return dt.strftime("%d %b %Y, %H:%M")
    except ValueError:
        pass
    return s[:32]


def _evidence_status_plain(raw) -> str:
    if raw is None or str(raw).strip() == "":
        return "Recorded"
    text = str(raw).strip().upper()
    if "VERIFIED" in text or "INTEGRITY" in text:
        return "Sealed — file not changed since collection"
    if "ERROR" in text:
        return "Problem — see case notes"
    return "Recorded"


def _hash_sha256_from_evidence(e: dict) -> str:
    h = e.get("sha256") or e.get("hash_sha256")
    return (str(h).strip() if h else "") or ""


def _hash_short_reference(h: str) -> str:
    if not h or len(h) < 16:
        return "—"
    clean = "".join(c for c in h.lower() if c in "0123456789abcdef")
    if len(clean) < 16:
        return "—"
    return f"{clean[:10]} … {clean[-8:]}"


def _attack_plain_sentence(attack) -> str:
    if not isinstance(attack, dict):
        return str(attack)
    ip = attack.get("suspicious_ip") or attack.get("ip") or "unknown address"
    attempts = attack.get("number_of_attempts", "")
    et = (attack.get("event_type") or "").lower()
    if "brute" in et:
        return f"We saw many failed sign-in attempts from {ip}" + (f" (about {attempts} tries)." if attempts else ".")
    if "failed" in et or "login" in et:
        return f"Failed sign-in activity was recorded from {ip}."
    return f"{attack.get('event_type', 'Activity')} involving {ip}."


def _p(text: str, style: ParagraphStyle) -> Paragraph:
    return Paragraph(escape(str(text)).replace("\n", "<br/>"), style)


def generate_forensic_report(
    output_path: str,
    case_id: str,
    case_name: str,
    investigator_name: str,
    evidence_summary: list,
    detected_attacks: list,
    suspicious_ips: list,
    timeline_events: list,
    conclusion: str = "Investigation in progress. Evidence has been collected and analyzed.",
    report_generated_at=None,
) -> str:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    generated_dt  = _parse_report_time(report_generated_at)
    generated_str = generated_dt.strftime("%d %B %Y at %H:%M")

    doc = SimpleDocTemplate(
        str(path),
        pagesize=A4,
        rightMargin=0.75 * inch,
        leftMargin=0.75 * inch,
        topMargin=0.7 * inch,
        bottomMargin=0.75 * inch,
    )
    styles = getSampleStyleSheet()

    title_style = ParagraphStyle("RepTitle", parent=styles["Heading1"],
        fontSize=20, textColor=NAVY, spaceAfter=6, leading=24)
    subtitle_style = ParagraphStyle("RepSubtitle", parent=styles["Normal"],
        fontSize=10, textColor=colors.HexColor("#4a5568"), spaceAfter=18, leading=14)
    section_num_style = ParagraphStyle("SecNum", parent=styles["Normal"],
        fontSize=11, textColor=NAVY_LIGHT, fontName="Helvetica-Bold", spaceBefore=16, spaceAfter=4, leading=14)
    section_title_style = ParagraphStyle("SecTitle", parent=styles["Normal"],
        fontSize=13, textColor=NAVY, fontName="Helvetica-Bold", spaceAfter=4, leading=16)
    hint_style = ParagraphStyle("SecHint", parent=styles["Normal"],
        fontSize=9, textColor=colors.HexColor("#718096"), spaceAfter=10, leading=12)
    body_style = ParagraphStyle("RepBody", parent=styles["Normal"],
        fontSize=10, leading=14, textColor=colors.HexColor("#2d3748"))
    bullet_style = ParagraphStyle("RepBullet", parent=body_style,
        leftIndent=12, bulletIndent=6, spaceBefore=3, spaceAfter=3)

    th = ParagraphStyle("TH", parent=styles["Normal"],
        fontSize=9, fontName="Helvetica-Bold", textColor=WHITE, leading=11)
    td = ParagraphStyle("TD", parent=styles["Normal"],
        fontSize=9, leading=12, textColor=colors.HexColor("#2d3748"))

    usable_w = A4[0] - 1.5 * inch
    story: List[Any] = []

    story.append(Paragraph("Security Investigation Report", title_style))
    story.append(Paragraph("A plain-English summary of this investigation.", subtitle_style))

    # Section 1 — Case overview
    story.append(Paragraph("Section 1 — Case Overview", section_num_style))
    story.append(Paragraph("Who and what this report is about", section_title_style))
    story.append(Paragraph("The reference number identifies this case in the online case file.", hint_style))

    case_rows = [
        [_p("Item", th), _p("Details", th)],
        [_p("Reference number", td), _p(case_id or "—", td)],
        [_p("Case title", td), _p(case_name or "—", td)],
        [_p("Investigator", td), _p(investigator_name or "—", td)],
        [_p("Report prepared", td), _p(generated_str, td)],
    ]
    case_tab = Table(case_rows, colWidths=[1.65 * inch, usable_w - 1.65 * inch])
    case_tab.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("GRID", (0, 0), (-1, -1), 0.25, STROKE),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, ROW_ALT]),
        ("LEFTPADDING", (0, 0), (-1, -1), 10),
        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
        ("TOPPADDING", (0, 0), (-1, -1), 7),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 7),
    ]))
    story.append(case_tab)

    # Section 2 — Evidence
    story.append(Paragraph("Section 2 — Items We Collected", section_num_style))
    story.append(Paragraph("Files and logs saved for this case", section_title_style))
    story.append(Paragraph("'Sealed' means we recorded a digital fingerprint — the file was not changed after collection.", hint_style))

    if evidence_summary:
        ev_rows = [[_p("What was collected", th), _p("When added", th), _p("Status", th)]]
        for e in evidence_summary[:30]:
            fn = e.get("file_name", "") or "—"
            ts = _friendly_date(e.get("timestamp_collected") or e.get("timestamp"))
            st = _evidence_status_plain(e.get("evidence_status"))
            h  = _hash_sha256_from_evidence(e)
            ref = _hash_short_reference(h)
            detail = escape(fn)
            if ref != "—":
                detail = f"{escape(fn)}<br/><font size=\"7\" color=\"#718096\">Fingerprint: {escape(ref)}</font>"
            ev_rows.append([Paragraph(detail, td), _p(ts, td), _p(st, td)])
        ev_tab = Table(ev_rows, colWidths=[usable_w * 0.46, usable_w * 0.28, usable_w * 0.26], repeatRows=1)
        ev_tab.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, STROKE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, ROW_ALT]),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        story.append(ev_tab)
    else:
        story.append(_p("No files have been added to this case yet.", body_style))

    # Section 3 — Unusual activity
    story.append(Paragraph("Section 3 — Unusual Activity", section_num_style))
    story.append(Paragraph("Things the automated checks flagged", section_title_style))
    story.append(Paragraph("Starting point for review — not a final legal finding.", hint_style))
    if detected_attacks:
        for attack in detected_attacks[:20]:
            story.append(Paragraph(f"• {escape(_attack_plain_sentence(attack))}", bullet_style))
    else:
        story.append(_p("Nothing was flagged in the last run, or log analysis was not run.", body_style))

    # Section 4 — IPs
    story.append(Paragraph("Section 4 — Internet Addresses to Review", section_num_style))
    story.append(Paragraph("Addresses that appeared in suspicious activity", section_title_style))
    story.append(Paragraph("These IP addresses showed up in connection with the events above.", hint_style))
    if suspicious_ips:
        ip_block = "• " + "<br/>• ".join(escape(str(ip)) for ip in suspicious_ips[:40])
        story.append(Paragraph(ip_block, body_style))
    else:
        story.append(_p("None listed for this report.", body_style))

    # Section 5 — Timeline
    story.append(Paragraph("Section 5 — Story in Order", section_num_style))
    story.append(Paragraph("What happened, step by step", section_title_style))
    story.append(Paragraph("Events are sorted by time so readers can follow the sequence.", hint_style))
    if timeline_events:
        tl_rows = [[_p("When", th), _p("What we observed", th)]]
        for ev in timeline_events[:35]:
            ts  = ev.get("time_str", "") or "—"
            evt = ev.get("event", ev.get("event_description", "")) or "—"
            tl_rows.append([_p(ts, td), _p(str(evt), td)])
        tl_tab = Table(tl_rows, colWidths=[1.15 * inch, usable_w - 1.15 * inch], repeatRows=1)
        tl_tab.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), NAVY),
            ("ALIGN", (0, 0), (-1, -1), "LEFT"),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("GRID", (0, 0), (-1, -1), 0.25, STROKE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [WHITE, ROW_ALT]),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 6),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ]))
        story.append(tl_tab)
    else:
        story.append(_p("No timeline was built for this report.", body_style))

    # Section 6 — Conclusion
    story.append(Paragraph("Section 6 — Summary and Next Steps", section_num_style))
    story.append(Paragraph("Plain-language closing", section_title_style))
    story.append(Paragraph("Decisions, recommendations, or what should happen next.", hint_style))
    story.append(Paragraph(escape(conclusion).replace("\n", "<br/>"), body_style))
    story.append(Spacer(1, 0.35 * inch))
    story.append(Paragraph("<i>End of report</i>",
        ParagraphStyle("End", parent=body_style, alignment=1, textColor=colors.HexColor("#718096"))))

    doc.build(story)
    return str(path)
