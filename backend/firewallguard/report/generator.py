"""Report generation: PDF, CSV, JSON and HTML.

The product specification calls for an executive report, a technical report and
CSV / JSON exports. This module renders all of them from the analysis
dictionary produced by ``firewallguard.pipeline``.

PDF rendering uses ReportLab's Platypus framework. All colours are defined once
in ``_PALETTE`` so the report carries consistent FirewallGuard AI branding.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import logging
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

import httpx
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    HRFlowable, KeepTogether,
)

_log = logging.getLogger("firewallguard.report")

_max_logo_w = 1.8 * inch
_max_logo_h = 0.9 * inch
_logo_timeout = 10.0
_logo_max_bytes = 2 * 1024 * 1024

_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _is_ip_private(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in n for n in _PRIVATE_NETS)
    except ValueError:
        return True


def _is_safe_url(url: str) -> bool:
    """Validate URL for SSRF protection: HTTPS only, no private/loopback IPs."""
    try:
        p = urlparse(url)
        if p.scheme != "https":
            _log.warning("Logo URL rejected: not HTTPS")
            return False
        if not p.hostname:
            return False
        try:
            infos = socket.getaddrinfo(p.hostname, None)
        except socket.gaierror:
            _log.warning("Logo URL rejected: DNS resolution failed")
            return False
        for f, _, _, _, sa in infos:
            if _is_ip_private(sa[0]):
                _log.warning("Logo URL rejected: resolves to private IP")
                return False
        return True
    except Exception:
        return False


def _load_logo(branding: Optional[Dict[str, Any]],
               max_width: float = _max_logo_w, max_height: float = _max_logo_h) -> Optional[Dict[str, Any]]:
    """Download a white-label logo and return a canvas-ready descriptor, or None.

    Returns a dict with:
      - 'type': 'svg' or 'raster'
      - 'drawing' (svg): a scaled svglib Drawing with drawOn()
      - 'buf' (raster): a BytesIO of PNG bytes
      - 'width', 'height': rendered dimensions in points
    """
    if not branding:
        return None
    url = (branding.get("logo_url") or "").strip()
    if not url:
        return None
    if not _is_safe_url(url):
        return None
    try:
        resp = httpx.get(url, timeout=_logo_timeout, follow_redirects=True)
        resp.raise_for_status()
        if len(resp.content) > _logo_max_bytes:
            _log.warning("Logo too large, skipping")
            return None
        ct = resp.headers.get("content-type", "").lower()
        content = resp.content
        is_svg = ("svg" in ct or
                  content.lstrip(b"<\x20").startswith(b"svg") or
                  b"<svg" in content[:2000])
        if is_svg:
            from svglib.svglib import svg2rlg
            drawing = svg2rlg(io.BytesIO(content))
            if drawing is None or drawing.width == 0 or drawing.height == 0:
                _log.warning("svglib failed to parse SVG logo")
                return None
            sx = max_width / drawing.width
            sy = max_height / drawing.height
            scale = min(sx, sy)
            drawing.scale(scale, scale)
            drawing.width *= scale
            drawing.height *= scale
            return {"type": "svg", "drawing": drawing, "width": drawing.width, "height": drawing.height}
        else:
            from PIL import Image as PILImage
            img = PILImage.open(io.BytesIO(content)).convert("RGBA")
            w, h = img.size
            px_w, px_h = w * inch / 72, h * inch / 72
            scale = min(max_width / px_w, max_height / px_h, 1.0)
            t_w = px_w * scale
            t_h = px_h * scale
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            buf.seek(0)
            return {"type": "raster", "buf": buf, "width": t_w, "height": t_h}
    except ImportError as e:
        _log.warning(f"SVG support unavailable: {e}")
        return None
    except Exception as e:
        _log.warning(f"Logo load failed for {url}: {e}")
        return None


_PALETTE = {
    "ink": colors.HexColor("#0f172a"),
    "slate": colors.HexColor("#334155"),
    "muted": colors.HexColor("#64748b"),
    "line": colors.HexColor("#e2e8f0"),
    "band": colors.HexColor("#f1f5f9"),
    "brand": colors.HexColor("#1d4ed8"),
    "Critical": colors.HexColor("#b91c1c"),
    "High": colors.HexColor("#ea580c"),
    "Medium": colors.HexColor("#ca8a04"),
    "Low": colors.HexColor("#0369a1"),
    "Info": colors.HexColor("#475569"),
}

_GRADE_COLOR = {
    "Secure": colors.HexColor("#15803d"),
    "A": colors.HexColor("#15803d"),
    "B": colors.HexColor("#65a30d"),
    "C": colors.HexColor("#ca8a04"),
    "D": colors.HexColor("#ea580c"),
    "F": colors.HexColor("#b91c1c"),
}

_STATUS_COLOR = {
    "open": colors.HexColor("#4f8cff"),
    "acknowledged": colors.HexColor("#f5c451"),
    "in_progress": colors.HexColor("#39d98a"),
    "fixed": colors.HexColor("#15803d"),
    "false_positive": colors.HexColor("#7a879b"),
    "accepted_risk": colors.HexColor("#7a879b"),
}

_STATUS_LABEL = {
    "open": "Open",
    "acknowledged": "Acknowledged",
    "in_progress": "In Progress",
    "fixed": "Fixed",
    "false_positive": "Dismissed",
    "accepted_risk": "Dismissed",
}


def _styles() -> Dict[str, ParagraphStyle]:
    base = getSampleStyleSheet()
    s: Dict[str, ParagraphStyle] = {}
    s["title"] = ParagraphStyle("fg_title", parent=base["Title"], fontName="Helvetica-Bold",
                                fontSize=24, textColor=_PALETTE["ink"], spaceAfter=4, alignment=TA_LEFT)
    s["subtitle"] = ParagraphStyle("fg_subtitle", parent=base["Normal"], fontSize=11,
                                   textColor=_PALETTE["muted"], spaceAfter=18)
    s["h2"] = ParagraphStyle("fg_h2", parent=base["Heading2"], fontName="Helvetica-Bold",
                             fontSize=14, textColor=_PALETTE["brand"], spaceBefore=16, spaceAfter=6)
    s["h3"] = ParagraphStyle("fg_h3", parent=base["Heading3"], fontName="Helvetica-Bold",
                             fontSize=11.5, textColor=_PALETTE["ink"], spaceBefore=10, spaceAfter=3)
    s["body"] = ParagraphStyle("fg_body", parent=base["Normal"], fontSize=9.5,
                               textColor=_PALETTE["slate"], leading=14, spaceAfter=6)
    s["small"] = ParagraphStyle("fg_small", parent=base["Normal"], fontSize=8,
                                textColor=_PALETTE["muted"], leading=11)
    s["cell"] = ParagraphStyle("fg_cell", parent=base["Normal"], fontSize=8.5,
                               textColor=_PALETTE["slate"], leading=12)
    s["cellb"] = ParagraphStyle("fg_cellb", parent=base["Normal"], fontSize=8.5,
                                fontName="Helvetica-Bold", textColor=_PALETTE["ink"], leading=12)
    s["cellh"] = ParagraphStyle("fg_cellh", parent=base["Normal"], fontSize=8.5,
                                fontName="Helvetica-Bold", textColor=colors.white, leading=12)
    return s


def _make_header_footer(branding: Optional[Dict[str, Any]] = None,
                        logo: Optional[Dict[str, Any]] = None):
    """Return a header/footer painter, optionally white-labelled for an MSP.

    ``branding`` may carry ``company_name``, ``primary_color`` and ``contact``.
    ``logo`` is a pre-loaded logo descriptor (dict from ``_load_logo``)
    drawn to the left of the company name in the header.
    When absent, the report carries default FirewallGuard AI branding.
    """
    b = branding or {}
    name = b.get("company_name") or "FirewallGuard AI"
    tagline = b.get("contact") or "Continuous Security Analysis for SonicWall Firewalls"
    try:
        brand_color = colors.HexColor(b["primary_color"]) if b.get("primary_color") else _PALETTE["brand"]
    except (ValueError, KeyError):
        brand_color = _PALETTE["brand"]

    def _header_footer(canvas_obj, doc):
        canvas_obj.saveState()
        x = 0.75 * inch
        y_text = letter[1] - 0.55 * inch
        if logo is not None:
            if logo.get("type") == "svg" and logo.get("drawing") is not None:
                logo["drawing"].drawOn(canvas_obj, x, y_text - 0.07 * inch)
                x += logo["width"] + 4
            elif logo.get("type") == "raster" and logo.get("buf") is not None:
                try:
                    canvas_obj.drawImage(logo["buf"], x, y_text - 0.07 * inch,
                                         width=logo["width"], height=logo["height"], mask="auto")
                    x += logo["width"] + 4
                except Exception:
                    pass
        canvas_obj.setFont("Helvetica-Bold", 11)
        canvas_obj.setFillColor(brand_color)
        canvas_obj.drawString(x, y_text, name)
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.setFillColor(_PALETTE["muted"])
        canvas_obj.drawRightString(letter[0] - 0.75 * inch, y_text, tagline)
        canvas_obj.setStrokeColor(_PALETTE["line"])
        canvas_obj.line(0.75 * inch, letter[1] - 0.72 * inch, letter[0] - 0.75 * inch, letter[1] - 0.72 * inch)
        canvas_obj.setFont("Helvetica", 8)
        canvas_obj.setFillColor(_PALETTE["muted"])
        canvas_obj.drawString(0.75 * inch, 0.5 * inch,
                              "Confidential - generated from customer-supplied TSR")
        canvas_obj.drawRightString(letter[0] - 0.75 * inch, 0.5 * inch, f"Page {doc.page}")
        canvas_obj.restoreState()

    return _header_footer


def _score_band(score: Dict[str, Any], st) -> Table:
    grade = score["grade"]
    gc = _GRADE_COLOR.get(grade, _PALETTE["ink"])
    big_grade = ParagraphStyle("fg_biggrade", fontName="Helvetica-Bold",
                               fontSize=38, leading=40, alignment=TA_CENTER,
                               textColor=gc)
    big_score = ParagraphStyle("fg_bigscore", fontName="Helvetica-Bold",
                               fontSize=30, leading=32, alignment=TA_CENTER,
                               textColor=_PALETTE["ink"])
    cap = ParagraphStyle("fg_cap", parent=st["small"], alignment=TA_CENTER, spaceBefore=2)

    left = Table([[Paragraph(grade, big_grade)],
                  [Paragraph(score["grade_label"], cap)]], colWidths=[1.15 * inch])
    right = Table([[Paragraph(f"{score['score']}", big_score)],
                   [Paragraph("Security Score", cap)]], colWidths=[1.35 * inch])
    mid = Table([[""]], colWidths=[0.3 * inch])
    t = Table([[left, mid, right]])
    t.setStyle(TableStyle([
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0),
        ("BACKGROUND", (0, 0), (-1, -1), _PALETTE["band"]),
        ("ROUNDEDCORNERS", [4, 4, 4, 4]),
    ]))
    return t


def _device_table(dev: Dict[str, Any], st) -> Table:
    rows = [
        [Paragraph("Model", st["cellb"]), Paragraph(dev.get("model", "-"), st["cell"])],
        [Paragraph("Firmware", st["cellb"]), Paragraph(dev.get("firmware", "-"), st["cell"])],
        [Paragraph("Serial", st["cellb"]), Paragraph(dev.get("serial", "-"), st["cell"])],
    ]
    t = Table(rows, colWidths=[1.2 * inch, 2.5 * inch])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, _PALETTE["line"]),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, _PALETTE["band"]]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return t


def _severity_chip(sev: str, st) -> Paragraph:
    c = _PALETTE.get(sev, _PALETTE["ink"])
    return Paragraph(f"<font color='{c.hexval()}'><b>{sev}</b></font>", st["cell"])


def _status_chip(status: str, st) -> Paragraph:
    """Render a color-coded status badge."""
    c = _STATUS_COLOR.get(status, _PALETTE["muted"])
    label = _STATUS_LABEL.get(status, status.replace("_", " ").title())
    return Paragraph(
        f"<font color='{c.hexval()}'><b>{label}</b></font>",
        ParagraphStyle("fg_status", parent=st["cell"], fontSize=8))


def _findings_status_summary(findings: List[Dict[str, Any]], st) -> Table:
    """Severity × Status cross-tab: Total, Open, Acknowledged, In Progress, Fixed, Dismissed."""
    severities = ["Critical", "High", "Medium", "Low", "Info"]
    statuses = ["total", "open", "acknowledged", "in_progress", "fixed", "dismissed"]
    status_labels_head = ["Total", "Open", "Acknowledged", "In Progress", "Fixed", "Dismissed"]
    mapped_dismissed = {"false_positive", "accepted_risk"}

    data: dict[str, dict[str, int]] = {}
    for sev in severities:
        data[sev] = {s: 0 for s in statuses}
    for f in findings:
        sev = f.get("severity", "Info")
        status = f.get("status", "open")
        if sev in data:
            data[sev]["total"] += 1
            if status in mapped_dismissed:
                data[sev]["dismissed"] += 1
            elif status in data[sev]:
                data[sev][status] += 1

    head = [Paragraph("Severity", st["cellh"])] + [Paragraph(l, st["cellh"]) for l in status_labels_head]
    rows = [head]
    sev_styles = [
        ParagraphStyle("sev_cell_" + sev, parent=st["cell"],
                       textColor=_PALETTE.get(sev, _PALETTE["muted"]))
        for sev in severities
    ]
    for i, sev in enumerate(severities):
        row = [Paragraph(sev, sev_styles[i])]
        for s in statuses:
            row.append(Paragraph(str(data[sev][s]), st["cell"]))
        rows.append(row)

    col_widths = [0.85 * inch] + [(5.15 * inch) / len(statuses)] * len(statuses)
    t = Table(rows, colWidths=col_widths, repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _PALETTE["ink"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _PALETTE["band"]]),
        ("GRID", (0, 0), (-1, -1), 0.4, _PALETTE["line"]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


def _findings_summary_table(findings: List[Dict[str, Any]], st, linked: bool = False) -> Table:
    """Findings index. When ``linked`` is true, each finding title links to its
    detail anchor (``finding-<n>``) so a reader can click through in the PDF."""
    head = [Paragraph(h, st["cellh"]) for h in
            ["#", "Severity", "Category", "Finding", "Affected Object", "Exploit."]]
    data = [head]
    for i, f in enumerate(findings, 1):
        title = f["title"]
        if linked:
            title_cell = Paragraph(
                f'<a href="#finding-{i}" color="#1d4ed8">{_esc(title)}</a>', st["cell"])
        else:
            title_cell = Paragraph(_esc(title), st["cell"])
        obj = f.get("object_name") or "-"
        obj_label = f"{obj}" if not f.get("object_type") else f"{obj}"
        data.append([
            Paragraph(str(i), st["cell"]),
            _severity_chip(f["severity"], st),
            Paragraph(_esc(f["category"]), st["cell"]),
            title_cell,
            Paragraph(_esc(obj_label[:60]), st["cell"]),
            Paragraph(f.get("exploitability", "-"), st["cell"]),
        ])
    t = Table(data, colWidths=[0.3 * inch, 0.7 * inch, 1.15 * inch, 2.2 * inch,
                               1.75 * inch, 0.65 * inch], repeatRows=1)
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _PALETTE["ink"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _PALETTE["band"]]),
        ("GRID", (0, 0), (-1, -1), 0.4, _PALETTE["line"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    return t


def _finding_detail(f: Dict[str, Any], n: int, st) -> List[Any]:
    """Render a single finding as a detail card."""
    out = []
    out.append(Paragraph(f'<a name="finding-{n}"/>', ParagraphStyle("anchor", parent=st["small"])))
    title_line = f"{_esc(f.get('severity',''))} &nbsp;|&nbsp; {_esc(f.get('title',''))}"
    out.append(Paragraph(title_line, st["h3"]))
    rows = []
    rows.append([Paragraph("Rule ID", st["cellb"]), Paragraph(f.get("rule_id", "-"), st["cell"])])
    rows.append([Paragraph("Category", st["cellb"]), Paragraph(f.get("category", "-"), st["cell"])])
    if f.get("object_type") or f.get("object_name"):
        rows.append([Paragraph("Affected Object", st["cellb"]),
                     Paragraph(f"{f.get('object_type','')} &gt; {f.get('object_name','')}", st["cell"])])
    if f.get("status"):
        rows.append([Paragraph("Status", st["cellb"]), _status_chip(f.get("status", "open"), st)])
    if f.get("exploitability"):
        rows.append([Paragraph("Exploitability", st["cellb"]), Paragraph(f.get("exploitability", ""), st["cell"])])
    if f.get("description"):
        rows.append([Paragraph("Description", st["cellb"]), Paragraph(f.get("description", ""), st["cell"])])
    if f.get("remediation"):
        rows.append([Paragraph("Remediation", st["cellb"]), Paragraph(f.get("remediation", ""), st["cell"])])
    if f.get("business_impact"):
        rows.append([Paragraph("Business Impact", st["cellb"]), Paragraph(f.get("business_impact", ""), st["cell"])])
    if f.get("technical_impact"):
        rows.append([Paragraph("Technical Impact", st["cellb"]), Paragraph(f.get("technical_impact", ""), st["cell"])])
    t = Table(rows, colWidths=[1.3 * inch, 4.5 * inch])
    t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, _PALETTE["line"]),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, _PALETTE["band"]]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 5), ("RIGHTPADDING", (0, 0), (-1, -1), 5),
    ]))
    out.append(t)
    out.append(Spacer(1, 10))
    return out


def _bullet_list(items: List[str], st) -> List[Any]:
    out = []
    for it in items:
        out.append(Paragraph(f"&bull;&nbsp; {it}", st["cell"]))
    return out


def _esc(text: Any) -> str:
    """Escape text for ReportLab's mini-markup so &, <, > render literally."""
    s = str(text)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ---------------------------------------------------------------------------
# Executive report
# ---------------------------------------------------------------------------

def build_executive_pdf(analysis: Dict[str, Any], path: str,
                        branding: Optional[Dict[str, Any]] = None) -> str:
    st = _styles()
    report_title = f"{(branding or {}).get('company_name', 'FirewallGuard AI')} - Executive Report"
    doc = SimpleDocTemplate(path, pagesize=letter,
                            topMargin=0.85 * inch, bottomMargin=0.8 * inch,
                            leftMargin=0.75 * inch, rightMargin=0.75 * inch,
                            title=report_title)
    story: List[Any] = []
    dev = analysis["device"]
    story.append(Paragraph("Executive Security Report", st["title"]))
    story.append(Paragraph(
        f"{dev.get('model','SonicWall device')} &nbsp;|&nbsp; Serial {dev.get('serial','-')} "
        f"&nbsp;|&nbsp; Generated {analysis.get('generated_at','')[:19].replace('T',' ')} UTC",
        st["subtitle"]))
    story.append(_score_band(analysis["score"], st))
    story.append(Spacer(1, 10))
    story.append(_device_table(dev, st))

    story.append(Paragraph("Findings overview", st["h2"]))
    story.append(_findings_summary_table(analysis["findings"], st))
    story.append(Spacer(1, 12))

    if analysis.get("attack_paths"):
        story.append(Paragraph("Top attack paths", st["h2"]))
        for ap in analysis["attack_paths"][:3]:
            story.append(Paragraph(
                f"{ap['path_id']} &middot; {ap['name']} [{ap['severity']}]", st["h3"]))
            story.append(Paragraph(ap.get("narrative", ""), st["body"]))
            story.append(Spacer(1, 6))

    _hf = _make_header_footer(branding)
    doc.build(story, onFirstPage=_hf, onLaterPages=_hf)
    return path


# ---------------------------------------------------------------------------
# Technical report (Device Findings)
# ---------------------------------------------------------------------------

def build_technical_pdf(analysis: Dict[str, Any], path: str,
                        branding: Optional[Dict[str, Any]] = None) -> str:
    st = _styles()
    report_title = f"{(branding or {}).get('company_name', 'FirewallGuard AI')} - Device Findings Report"
    doc = SimpleDocTemplate(path, pagesize=letter,
                            topMargin=0.75 * inch, bottomMargin=0.7 * inch,
                            leftMargin=0.7 * inch, rightMargin=0.7 * inch,
                            title=report_title)
    story: List[Any] = []
    dev = analysis["device"]
    score = analysis.get("score", {})
    findings = analysis.get("findings", [])
    generated = analysis.get("generated_at", "")[:19].replace("T", " ")

    # =====================================================================
    # 1. REPORT HEADER / COVER
    # =====================================================================
    _logo = _load_logo(branding, max_width=0.35 * inch, max_height=0.35 * inch)
    story.append(Paragraph("Device Security Assessment Report", st["title"]))
    story.append(Paragraph(
        f"{dev.get('model','SonicWall device')} &nbsp;|&nbsp; "
        f"Firmware {dev.get('firmware','-')} &nbsp;|&nbsp; "
        f"Serial {dev.get('serial','-')}",
        st["subtitle"]))
    story.append(Paragraph(f"Generated {generated} UTC", st["small"]))
    story.append(Spacer(1, 10))

    # =====================================================================
    # 2. EXECUTIVE SUMMARY
    # =====================================================================
    story.append(Paragraph("Executive Summary", st["h2"]))

    # Score band
    story.append(_score_band(score, st))
    story.append(Spacer(1, 10))

    # Combined Device Overview panel
    total_active = sum(
        1 for f in findings
        if f.get("status", "open") in {"open", "acknowledged", "in_progress"}
    )
    total_resolved = sum(
        1 for f in findings
        if f.get("status", "open") in {"fixed", "false_positive", "accepted_risk"}
    )
    overview = [
        [Paragraph("Device", st["cellb"]), Paragraph(dev.get("model", "-"), st["cell"])],
        [Paragraph("Serial", st["cellb"]), Paragraph(dev.get("serial", "-"), st["cell"])],
        [Paragraph("Firmware", st["cellb"]), Paragraph(dev.get("firmware", "-"), st["cell"])],
        [Paragraph("Report Generated", st["cellb"]), Paragraph(generated + " UTC", st["cell"])],
        [Paragraph("Total Findings", st["cellb"]), Paragraph(str(len(findings)), st["cell"])],
        [Paragraph("Active (Open / In Progress)", st["cellb"]), Paragraph(str(total_active), st["cell"])],
        [Paragraph("Resolved (Fixed / Dismissed)", st["cellb"]), Paragraph(str(total_resolved), st["cell"])],
    ]
    overview_t = Table(overview, colWidths=[2.2 * inch, 3.8 * inch])
    overview_t.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.4, _PALETTE["line"]),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, _PALETTE["band"]]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(Paragraph("Device Overview", st["h3"]))
    story.append(overview_t)
    story.append(Spacer(1, 14))

    # =====================================================================
    # 3. FINDINGS SUMMARY by Severity x Status (on same page)
    # =====================================================================
    story.append(Paragraph("Findings Summary", st["h2"]))
    story.append(Paragraph(
        "Breakdown of all findings by severity and current triage status.",
        st["small"]))
    story.append(Spacer(1, 6))
    story.append(_findings_status_summary(findings, st))
    story.append(PageBreak())

    # =====================================================================
    # 4. DETAILED FINDINGS INDEX with status column
    # =====================================================================
    story.append(Paragraph("Detailed Findings", st["h2"]))
    story.append(Paragraph("Tip: click any finding title to jump to its full detail card.", st["small"]))
    story.append(Spacer(1, 4))

    head = [Paragraph(h, st["cellh"]) for h in
            ["#", "Sev", "Status", "Category", "Finding", "Affected Object", "Expl."]]
    data_rows = [head]
    for i, f in enumerate(findings, 1):
        title = f["title"]
        title_cell = Paragraph(
            f'<a href="#finding-{i}" color="#1d4ed8">{_esc(title)}</a>', st["cell"])
        obj = f.get("object_name") or "-"
        data_rows.append([
            Paragraph(str(i), st["cell"]),
            _severity_chip(f["severity"], st),
            _status_chip(f.get("status", "open"), st),
            Paragraph(_esc(f["category"]), st["cell"]),
            title_cell,
            Paragraph(_esc(obj[:60]), st["cell"]),
            Paragraph(f.get("exploitability", "-"), st["cell"]),
        ])

    col_widths_idx = [0.28 * inch, 0.68 * inch, 0.55 * inch, 0.9 * inch, 1.94 * inch, 1.5 * inch, 0.55 * inch]
    t_idx = Table(data_rows, colWidths=col_widths_idx, repeatRows=1)
    t_idx.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _PALETTE["ink"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _PALETTE["band"]]),
        ("GRID", (0, 0), (-1, -1), 0.4, _PALETTE["line"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(t_idx)
    story.append(PageBreak())

    # =====================================================================
    # 5. DETAILED FINDING CARDS
    # =====================================================================
    story.append(Paragraph("Finding Details", st["h2"]))
    for i, f in enumerate(findings, 1):
        for flow in _finding_detail(f, i, st):
            story.append(flow)

    # =====================================================================
    # 6. ATTACK PATHS (if any)
    # =====================================================================
    if analysis.get("attack_paths"):
        story.append(PageBreak())
        story.append(Paragraph("Attack Path Analysis", st["h2"]))
        for ap in analysis["attack_paths"]:
            story.append(Paragraph(f"{ap['path_id']} &middot; {ap['name']} [{ap['severity']}]", st["h3"]))
            story.append(Paragraph(ap.get("narrative", ""), st["body"]))
            for s_i, stage in enumerate(ap.get("stages", []), 1):
                if isinstance(stage, dict):
                    label = stage.get("stage", f"Stage {s_i}")
                    detail = stage.get("detail", "")
                    story.append(Paragraph(f"&bull; <b>{label}:</b> {detail}", st["cell"]))
                else:
                    story.append(Paragraph(f"&bull; <b>Stage {s_i}:</b> {stage}", st["cell"]))
            if ap.get("contributing_rules"):
                story.append(Paragraph(
                    f"<i>Contributing rules: {', '.join(ap['contributing_rules'])}</i>", st["small"]))
            story.append(Spacer(1, 8))

    _hf = _make_header_footer(branding, logo=_logo)
    doc.build(story, onFirstPage=_hf, onLaterPages=_hf)
    return path


# ---------------------------------------------------------------------------
# TSR comparison report
# ---------------------------------------------------------------------------

def _fp(d: dict) -> str:
    return f"{d.get('rule_id','')}::{d.get('object_type','')}::{d.get('object_name','')}"


def build_comparison_pdf(previous: Dict[str, Any], current: Dict[str, Any],
                         path: str, branding: Optional[Dict[str, Any]] = None) -> str:
    """Generate a TSR comparison report as a PDF, saved to ``path``.

    ``previous`` and ``current`` are the analysis result dicts for the older
    and newer TSR respectively.
    """
    st = _styles()
    report_title = f"{(branding or {}).get('company_name', 'FirewallGuard AI')} - TSR Comparison Report"
    doc = SimpleDocTemplate(path, pagesize=letter,
                            topMargin=0.7 * inch, bottomMargin=0.6 * inch,
                            leftMargin=0.6 * inch, rightMargin=0.6 * inch,
                            title=report_title)
    story: List[Any] = []

    prev_dev = previous.get("device", {})
    curr_dev = current.get("device", {})
    prev_score = previous.get("score", {})
    curr_score = current.get("score", {})
    prev_findings = previous.get("findings", [])
    curr_findings = current.get("findings", [])
    prev_keys = {_fp(f) for f in prev_findings}
    curr_keys = {_fp(f) for f in curr_findings}
    new_findings = [f for f in curr_findings if _fp(f) not in prev_keys]
    resolved_findings = [f for f in prev_findings if _fp(f) not in curr_keys]

    # Title
    story.append(Paragraph("TSR Comparison Report", st["title"]))
    story.append(Paragraph(
        f"{curr_dev.get('model','Device')} &nbsp;|&nbsp; Serial {curr_dev.get('serial','-')} "
        f"&nbsp;|&nbsp; Generated {current.get('generated_at','')[:19].replace('T',' ')} UTC",
        st["subtitle"]))
    story.append(Spacer(1, 6))

    # Score comparison
    score_data = [
        ["Metric", "Older TSR", "Newer TSR", "\u0394"],
        ["Score", str(prev_score.get("score", "\u2014")), str(curr_score.get("score", "\u2014")),
         f"{(curr_score.get('score',0) or 0) - (prev_score.get('score',0) or 0):+.0f}"],
        ["Grade", str(prev_score.get("grade", "\u2014")), str(curr_score.get("grade", "\u2014")), "\u2014"],
        ["Findings", str(previous.get("finding_count", 0)), str(current.get("finding_count", 0)),
         (current.get("finding_count", 0) or 0) - (previous.get("finding_count", 0) or 0)],
    ]
    t = Table(score_data, colWidths=[1.4 * inch, 1.5 * inch, 1.5 * inch, 0.8 * inch])
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _PALETTE["ink"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, _PALETTE["line"]),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5), ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (0, 1), (-1, -1), _PALETTE["band"]),
    ]))
    story.append(Paragraph("Score Comparison", st["h2"]))
    story.append(t)
    story.append(Spacer(1, 8))

    # Summary counts
    story.append(Paragraph("Change Summary", st["h2"]))
    summary_data = [
        ["Metric", "Count"],
        ["New Findings", str(len(new_findings))],
        ["Resolved Findings", str(len(resolved_findings))],
    ]
    # Severity breakdown of new findings
    sev_counts: dict[str, int] = {}
    for f in new_findings:
        sev = f.get("severity", "Info")
        sev_counts[sev] = sev_counts.get(sev, 0) + 1
    for sev in ["Critical", "High", "Medium", "Low", "Info"]:
        if sev_counts.get(sev):
            summary_data.append([f"  New {sev}", str(sev_counts[sev])])

    st_t = Table(summary_data, colWidths=[3 * inch, 1.2 * inch])
    st_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _PALETTE["ink"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.4, _PALETTE["line"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 4), ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    story.append(st_t)
    story.append(Spacer(1, 12))

    # Side-by-side findings table
    story.append(Paragraph("Side-by-Side Comparison", st["h2"]))
    all_keys = set()
    pmap: dict[str, dict] = {}
    cmap: dict[str, dict] = {}
    for f in prev_findings:
        k = _fp(f); all_keys.add(k); pmap[k] = f
    for f in curr_findings:
        k = _fp(f); all_keys.add(k); cmap[k] = f

    rows = []
    for k in sorted(all_keys):
        f = cmap.get(k) or pmap.get(k)
        sev = f.get("severity", "Info")
        title = _esc(f.get("title", "")[:100])
        in_old = "Yes" if k in pmap else "\u2014"
        in_new = "Yes" if k in cmap else "\u2014"
        rows.append([Paragraph(title, st["cell"]),
                     Paragraph(sev, ParagraphStyle("sev", parent=st["cell"],
                        textColor=_PALETTE.get(sev, _PALETTE["muted"]))),
                     Paragraph(in_old, st["cell"]),
                     Paragraph(in_new, st["cell"])])

    # Sort by severity
    sev_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    rows.sort(key=lambda r: sev_order.get(r[1].text, 9))

    header = [Paragraph("Finding", st["cellh"]), Paragraph("Sev", st["cellh"]),
              Paragraph("Older TSR", st["cellh"]), Paragraph("Newer TSR", st["cellh"])]
    sbs_data = [header] + rows
    sbs_t = Table(sbs_data, colWidths=[4.2 * inch, 0.7 * inch, 0.75 * inch, 0.75 * inch], repeatRows=1)
    sbs_t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), _PALETTE["ink"]),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, _PALETTE["band"]]),
        ("GRID", (0, 0), (-1, -1), 0.3, _PALETTE["line"]),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("LEFTPADDING", (0, 0), (-1, -1), 4), ("RIGHTPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(sbs_t)

    _hf = _make_header_footer(branding)
    doc.build(story, onFirstPage=_hf, onLaterPages=_hf)
    return path


# ---------------------------------------------------------------------------
# Data exports
# ---------------------------------------------------------------------------

def export_findings_csv(analysis: Dict[str, Any], path: str) -> str:
    cols = ["rule_id", "title", "severity", "category", "exploitability",
            "affected_count", "likelihood", "impact", "exposure",
            "risk_reduction", "description", "business_impact",
            "technical_impact", "remediation"]
    with open(path, "w", newline="", encoding="utf-8") as fh:
        w = csv.writer(fh)
        w.writerow(cols)
        for f in analysis["findings"]:
            w.writerow([f.get(c, "") for c in cols])
    return path


def export_json(analysis: Dict[str, Any], path: str, include_snapshot: bool = False) -> str:
    payload = dict(analysis)
    if not include_snapshot:
        payload = {k: v for k, v in analysis.items() if k != "snapshot"}
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, default=str)
    return path


def to_csv_string(analysis: Dict[str, Any]) -> str:
    buf = io.StringIO()
    cols = ["rule_id", "title", "severity", "category", "exploitability", "affected_count"]
    w = csv.writer(buf)
    w.writerow(cols)
    for f in analysis["findings"]:
        w.writerow([f.get(c, "") for c in cols])
    return buf.getvalue()
