"""Report renderers: HTML (Jinja2 + inline SVG charts), PDF (ReportLab), JSON and a CSV bundle (ZIP).

ReportLab is used for PDF because it is pure Python and works identically on
Windows, Linux and in Docker (no GTK/wkhtmltopdf system dependencies).
"""

from __future__ import annotations

import csv
import html
import io
import json
import re
import zipfile
from pathlib import Path
from typing import Any

from jinja2 import Environment, FileSystemLoader, select_autoescape

TEMPLATES = Path(__file__).resolve().parents[2] / "templates"
SEV_COLORS = {"critical": "#b42318", "high": "#d9480f", "medium": "#b08900", "low": "#2f6fb0", "info": "#667085"}
BAND_COLORS = {"critical": "#b42318", "high": "#d9480f", "moderate": "#b08900", "low": "#2f6fb0"}


# ---------------------------------------------------------------------- helpers
def _md_to_html(text: str | None) -> str:
    """Minimal, safe Markdown subset (escape first, then headings/bold/code/lists)."""
    if not text:
        return ""
    out, in_list = [], None
    for raw in html.escape(text).splitlines():
        line = re.sub(r"\*\*(.+?)\*\*", r"<strong>\1</strong>", raw)
        line = re.sub(r"`([^`]+)`", r"<code>\1</code>", line)
        m_ul, m_ol = re.match(r"^\s*-\s+(.*)", line), re.match(r"^\s*\d+\.\s+(.*)", line)
        tag = "ul" if m_ul else "ol" if m_ol else None
        if in_list and tag != in_list:
            out.append(f"</{in_list}>")
            in_list = None
        if tag:
            if not in_list:
                out.append(f"<{tag}>")
                in_list = tag
            out.append(f"<li>{(m_ul or m_ol).group(1)}</li>")
        elif line.startswith("### "):
            out.append(f"<h4>{line[4:]}</h4>")
        elif line.startswith("&gt; "):
            out.append(f"<blockquote>{line[5:]}</blockquote>")
        elif line.strip() in ("---", ""):
            out.append("")
        else:
            out.append(f"<p>{line}</p>")
    if in_list:
        out.append(f"</{in_list}>")
    return "\n".join(out)


def _svg_bars(items: list[tuple[str, int, str]], width: int = 520, bar_h: int = 22) -> str:
    """Horizontal bar chart as inline SVG (label, value, colour)."""
    if not items:
        return "<p class='muted'>No data.</p>"
    maxv = max(v for _, v, _ in items) or 1
    label_w, gap = 170, 8
    h = len(items) * (bar_h + gap)
    rows = []
    for i, (label, value, color) in enumerate(items):
        y = i * (bar_h + gap)
        w = max(2, int((width - label_w - 50) * value / maxv)) if value else 0
        rows.append(f"<text x='{label_w - 8}' y='{y + bar_h * 0.7}' text-anchor='end' font-size='12' "
                    f"fill='#344054'>{html.escape(label)}</text>"
                    f"<rect x='{label_w}' y='{y}' width='{w}' height='{bar_h}' rx='3' fill='{color}'/>"
                    f"<text x='{label_w + w + 6}' y='{y + bar_h * 0.7}' font-size='12' fill='#344054'>{value}</text>")
    return f"<svg width='{width}' height='{h}' role='img' xmlns='http://www.w3.org/2000/svg'>{''.join(rows)}</svg>"


def _charts(data: dict[str, Any]) -> dict[str, str]:
    s = data.get("summary") or {}
    sev = s.get("severity_counts") or {}
    top = [p for p in data["processes"] if p["risk_score"] > 0][:10]
    cats = sorted((s.get("category_counts") or {}).items(), key=lambda kv: -kv[1])
    return {
        "severity": _svg_bars([(k.title(), sev.get(k, 0), SEV_COLORS[k]) for k in
                               ("critical", "high", "medium", "low", "info")]),
        "top_processes": _svg_bars([(f"{p['name']} ({p['pid']})", p["risk_score"],
                                     BAND_COLORS.get(p["risk_band"], "#667085")) for p in top]),
        "categories": _svg_bars([(k.replace("_", " "), v, "#475467") for k, v in cats]),
    }


# ---------------------------------------------------------------------- HTML
def render_html(data: dict[str, Any]) -> bytes:
    env = Environment(loader=FileSystemLoader(str(TEMPLATES)), autoescape=select_autoescape(["html", "j2"]))
    env.filters["md"] = _md_to_html
    tpl = env.get_template("report.html.j2")
    return tpl.render(d=data, charts=_charts(data), sev_colors=SEV_COLORS, band_colors=BAND_COLORS).encode("utf-8")


# ---------------------------------------------------------------------- JSON / CSV
def render_json(data: dict[str, Any]) -> bytes:
    return json.dumps(data, indent=2, default=str).encode("utf-8")


def _csv(rows: list[dict[str, Any]], fields: list[str]) -> str:
    buf = io.StringIO()
    w = csv.DictWriter(buf, fieldnames=fields, extrasaction="ignore")
    w.writeheader()
    for r in rows:
        w.writerow({k: (json.dumps(v) if isinstance(v, (list, dict)) else v) for k, v in r.items()})
    return buf.getvalue()


def render_csv_bundle(data: dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("findings.csv", _csv(data["findings"], ["id", "severity", "rule_id", "title", "process_name", "pid",
                                                           "confidence", "category", "finding", "recommendation",
                                                           "status", "evidence"]))
        z.writestr("processes.csv", _csv(data["processes"], ["pid", "ppid", "name", "path", "cmdline", "create_time",
                                                             "exit_time", "sources", "hidden", "risk_score",
                                                             "risk_band"]))
        z.writestr("network.csv", _csv(data["network"], ["pid", "owner", "protocol", "local", "foreign", "state",
                                                         "created", "external", "suspicious", "reason"]))
        z.writestr("iocs.csv", _csv(data["iocs"], ["type", "value", "source", "process", "pid", "confidence",
                                                   "context", "watchlist"]))
        z.writestr("timeline.csv", _csv(data["timeline"], ["timestamp", "timestamp_source", "pid", "process",
                                                           "event", "description", "severity", "ref"]))
        z.writestr("chain_of_custody.csv", _csv(data["custody"], ["timestamp", "action", "actor", "details",
                                                                  "sha256"]))
        if data["is_demo"]:
            z.writestr("DEMO_DATA_NOTICE.txt", "DEMO DATA - NOT REAL FORENSIC EVIDENCE. Generated from the synthetic "
                                               "demonstration dataset.\n")
    return buf.getvalue()


# ---------------------------------------------------------------------- PDF
def render_pdf(data: dict[str, Any]) -> bytes:
    from reportlab.graphics.charts.barcharts import HorizontalBarChart
    from reportlab.graphics.shapes import Drawing
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
    from reportlab.lib.units import mm
    from reportlab.platypus import PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

    styles = getSampleStyleSheet()
    body = ParagraphStyle("body", parent=styles["BodyText"], fontSize=9, leading=12)
    small = ParagraphStyle("small", parent=body, fontSize=7.5, leading=9.5)
    h1, h2 = styles["Heading1"], ParagraphStyle("h2", parent=styles["Heading2"], spaceBefore=10)
    banner = ParagraphStyle("banner", parent=body, textColor=colors.white, backColor=colors.HexColor("#b42318"),
                            alignment=1, fontSize=10, leading=14, borderPadding=4)

    def p(text: Any, style=body) -> Paragraph:
        return Paragraph(html.escape(str(text if text is not None else "-")), style)

    def table(rows: list[list[Any]], widths: list[float], header=True) -> Table:
        t = Table([[c if isinstance(c, Paragraph) else p(c, small) for c in r] for r in rows], colWidths=widths,
                  repeatRows=1 if header else 0)
        style = [("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#d0d5dd")),
                 ("VALIGN", (0, 0), (-1, -1), "TOP")]
        if header:
            style.append(("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#eaecf0")))
        t.setStyle(TableStyle(style))
        return t

    def bar_chart(items: list[tuple[str, int]], color: str) -> Drawing:
        d = Drawing(170 * mm, max(30, 9 * mm * len(items)))
        if not items:
            return d
        c = HorizontalBarChart()
        c.x, c.y = 45 * mm, 5
        c.width, c.height = 115 * mm, max(20, 9 * mm * len(items) - 10)
        c.data = [[v for _, v in items]]
        c.categoryAxis.categoryNames = [k for k, _ in items]
        c.categoryAxis.labels.fontSize = 7
        c.valueAxis.valueMin = 0
        c.valueAxis.labels.fontSize = 7
        c.bars[0].fillColor = colors.HexColor(color)
        d.add(c)
        return d

    W = 180 * mm
    story: list[Any] = []
    if data["is_demo"]:
        story += [Paragraph("DEMO DATA - NOT REAL FORENSIC EVIDENCE", banner), Spacer(1, 6)]
    story += [Paragraph("Windows Memory Forensics Report", h1),
              p(f"Case {data['case']['number']} - {data['case']['title']}"),
              p(f"Generated {data['generated_at']} by {data['generated_by']}", small), Spacer(1, 8)]

    a, img, s = data["analysis"], data["image"], data["summary"] or {}
    story += [Paragraph("1. Executive Summary", h2)]
    for line in (data.get("executive_summary") or "").splitlines():
        line = re.sub(r"[#*`>]", "", line).strip()
        if line:
            story.append(p(line))
    story += [Spacer(1, 4), p(f"Overall analytical risk: {a['overall_risk_score']} ({a['overall_risk_band']}). "
                                "Project scoring model - not an authoritative malware verdict.")]

    story += [Paragraph("2-5. Case, Evidence and Environment", h2), table([
        ["Case number", data["case"]["number"]], ["Investigator", data["case"]["investigator"]],
        ["Evidence file", img["filename"]], ["SHA-256", img["sha256"]], ["Size (bytes)", img["size_bytes"]],
        ["Format", img["format"]], ["Uploaded", img["uploaded_at"]],
        ["Operating system", (img["os_info"] or {}).get("os_name") or "unknown"],
        ["Architecture", (img["os_info"] or {}).get("architecture") or "unknown"],
        ["Build", (img["os_info"] or {}).get("build") or "unknown"],
        ["Identification confidence", (img["os_info"] or {}).get("confidence")],
        ["Volatility", a["volatility_version"]], ["Analysis", f"#{a['id']} {a['status']}"],
        ["Hash verified before/after", f"{a['hash_verified_before']} / {a['hash_verified_after']}"],
    ], [45 * mm, W - 45 * mm], header=False)]

    story += [Paragraph("6. Analysis Methodology", h2)] + [p(f"- {m}") for m in data["methodology"]]
    story += [Spacer(1, 4), table([["Plugin", "Status", "Rows", "ms", "Args / error"]] + [
        [x["plugin"], x["status"], x["rows"], x["duration_ms"], (x["args"] or "") + (" " + x["error"] if x["error"] else "")]
        for x in data["plugins"]], [42 * mm, 18 * mm, 14 * mm, 14 * mm, W - 88 * mm])]

    story += [PageBreak(), Paragraph("7-8. Process Analysis and Suspicious Processes", h2),
              p(f"{s.get('total_processes', 0)} processes reconstructed ({s.get('hidden_candidates', 0)} hidden "
                f"candidates, {s.get('terminated_processes', 0)} terminated)."),
              bar_chart([(f"{x['name'][:18]} ({x['pid']})", x["risk_score"]) for x in data["processes"]
                         if x["risk_score"] > 0][:10][::-1], "#d9480f")]
    for proc in [x for x in data["processes"] if x["risk_score"] >= 30]:
        story += [Spacer(1, 4), p(f"{proc['name']} PID {proc['pid']} (PPID {proc['ppid']}) - risk {proc['risk_score']} "
                                  f"({proc['risk_band']})"),
                  p(f"Path: {proc['path'] or 'unknown'}", small), p(f"Command line: {proc['cmdline'] or '-'}", small),
                  p("Score contributors: " + "; ".join(f"{c['points']:+d} {c['label']}" for c in proc["contributors"]),
                    small)]

    sev = s.get("severity_counts") or {}
    story += [Paragraph("Findings", h2), bar_chart([(k, sev.get(k, 0)) for k in
                                                    ("info", "low", "medium", "high", "critical")], "#475467"),
              table([["Sev", "Rule", "Process", "Conf", "Finding"]] + [
                  [f["severity"], f["rule_id"], f"{f['process_name']} ({f['pid']})", f["confidence"], f["finding"]]
                  for f in data["findings"]], [14 * mm, 38 * mm, 30 * mm, 10 * mm, W - 92 * mm])]

    story += [Paragraph("9. Memory Injection Findings", h2)]
    story += [table([["PID", "Process", "Region", "Protection", "PE", "First bytes"]] + [
        [r["pid"], r["process"], f"{r['start']}-{r['end']}", r["protection"], "yes" if r["pe_header"] else "no",
         (r["first_line"] or "")[:48]] for r in data["memory_regions"]],
        [12 * mm, 26 * mm, 42 * mm, 36 * mm, 8 * mm, W - 124 * mm])] if data["memory_regions"] else [
        p("malfind reported no regions.")]

    story += [Paragraph("10. Network Analysis", h2)]
    story += [table([["PID", "Owner", "Proto", "Local", "Foreign", "State", "Flag"]] + [
        [c["pid"], c["owner"], c["protocol"], c["local"], c["foreign"], c["state"], c["reason"] or ""]
        for c in data["network"]], [11 * mm, 24 * mm, 13 * mm, 32 * mm, 34 * mm, 22 * mm, W - 136 * mm])] \
        if data["network"] else [p("No network endpoints recovered.")]

    story += [Paragraph("11. IOC Findings", h2)]
    story += [table([["Type", "Value", "Source", "Process", "Conf"]] + [
        [i["type"], i["value"][:150], i["source"], f"{i['process'] or '-'} ({i['pid']})", i["confidence"]]
        for i in data["iocs"]], [20 * mm, 78 * mm, 30 * mm, 36 * mm, W - 164 * mm])] if data["iocs"] else [
        p("No IOCs extracted.")]

    story += [Paragraph("12. YARA Findings", h2)]
    story += [table([["Rule", "PID", "Process", "Offset", "Severity"]] + [
        [y["rule"], y["pid"], y["process"], y["offset"], y["severity"]] for y in data["yara"]],
        [60 * mm, 15 * mm, 40 * mm, 35 * mm, W - 150 * mm])] if data["yara"] else [
        p("No YARA matches (or YARA scanning not performed).")]

    model = data.get("scoring_model") or {}
    story += [Paragraph("13. Risk Scoring Methodology", h2), p(model.get("formula", "")),
              p("Bands: " + ", ".join(f"{b['name']} {b['min']}-{b['max']}" for b in model.get("bands", []))),
              p(model.get("disclaimer", ""))]

    story += [Paragraph("14. AI Analysis", h2),
              p(f"Executive summary produced by: {data.get('executive_summary_provider') or 'n/a'}. All AI text is "
                f"generated from retrieved evidence and validated against the evidence store.")]
    for f in [f for f in data["findings"] if f.get("explanation")][:10]:
        e = f["explanation"]
        story += [Spacer(1, 3), p(f"[F-{f['id']}] {f['title']}"), p(f"What happened: {e.get('what_happened')}", small),
                  p(f"Why suspicious: {e.get('why_suspicious')}", small),
                  p(f"Does NOT prove: {e.get('does_not_prove')}", small)]

    story += [Paragraph("15. Timeline", h2), table([["Timestamp (UTC)", "PID", "Event", "Description"]] + [
        [t["timestamp"] or "unavailable", t["pid"], t["event"], t["description"][:200]]
        for t in data["timeline"] if t["severity"] != "info" or t["event"] != "process_created"][:120],
        [38 * mm, 12 * mm, 32 * mm, W - 82 * mm])]

    story += [Paragraph("16. Limitations", h2)] + [p(f"- {x}") for x in data["limitations"]]
    story += [Paragraph("17. Recommended Next Steps", h2)] + [p(f"{i}. {x}") for i, x in
                                                               enumerate(data["next_steps"], 1)]
    story += [PageBreak(), Paragraph("18. Appendix - Chain of Custody", h2), table(
        [["Timestamp", "Action", "Actor", "Details / SHA-256"]] + [
            [c["timestamp"], c["action"], c["actor"], (c["details"] or "") + (f" {c['sha256']}" if c["sha256"] else "")]
            for c in data["custody"]], [38 * mm, 30 * mm, 36 * mm, W - 104 * mm])]
    story += [Paragraph("Appendix - Plugin Rationale and Output Hashes", h2), table(
        [["Plugin", "Why it was run", "Output SHA-256"]] + [
            [x["plugin"], x["rationale"], x["output_sha256"] or "-"] for x in data["plugins"]],
        [36 * mm, 90 * mm, W - 126 * mm])]

    def on_page(canvas, doc) -> None:
        canvas.saveState()
        canvas.setFont("Helvetica", 7)
        footer = f"Case {data['case']['number']}  |  Evidence SHA-256 {data['image']['sha256'][:32]}...  |  page {doc.page}"
        if data["is_demo"]:
            footer = "DEMO DATA - NOT REAL EVIDENCE  |  " + footer
        canvas.drawString(15 * mm, 10 * mm, footer)
        canvas.restoreState()

    buf = io.BytesIO()
    SimpleDocTemplate(buf, pagesize=A4, leftMargin=15 * mm, rightMargin=15 * mm, topMargin=15 * mm,
                      bottomMargin=18 * mm, title=f"Forensic report {data['case']['number']}",
                      author="MemTrace").build(story, onFirstPage=on_page, onLaterPages=on_page)
    return buf.getvalue()


RENDERERS = {"html": (render_html, "text/html"), "pdf": (render_pdf, "application/pdf"),
             "json": (render_json, "application/json"), "csv": (render_csv_bundle, "application/zip")}
EXTENSIONS = {"html": "html", "pdf": "pdf", "json": "json", "csv": "zip"}
