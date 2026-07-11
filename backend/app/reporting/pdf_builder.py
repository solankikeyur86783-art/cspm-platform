import io
from datetime import datetime
from typing import List, Dict, Any, Optional

from app.core.logging import logger

# Severity colors
SEVERITY_COLORS = {
    "critical": (0.80, 0.10, 0.10),
    "high": (0.90, 0.45, 0.10),
    "medium": (0.90, 0.75, 0.10),
    "low": (0.20, 0.60, 0.20),
    "info": (0.30, 0.50, 0.80),
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]


class PDFReportBuilder:
    def build(self, scan, findings: list, title: str, config: dict) -> bytes:
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
            from reportlab.lib.units import cm
            from reportlab.lib import colors
            from reportlab.platypus import (
                SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
                HRFlowable, PageBreak, KeepTogether,
            )
            from reportlab.lib.enums import TA_CENTER, TA_LEFT

            buffer = io.BytesIO()
            doc = SimpleDocTemplate(
                buffer,
                pagesize=A4,
                rightMargin=2 * cm,
                leftMargin=2 * cm,
                topMargin=2 * cm,
                bottomMargin=2 * cm,
                title=title,
                author="CSPM Platform",
            )

            styles = getSampleStyleSheet()
            story = []

            # ── Cover Page ────────────────────────────────────────────
            title_style = ParagraphStyle(
                "CoverTitle",
                parent=styles["Title"],
                fontSize=26,
                textColor=colors.HexColor("#1A1A2E"),
                spaceAfter=12,
            )
            subtitle_style = ParagraphStyle(
                "Subtitle",
                parent=styles["Normal"],
                fontSize=14,
                textColor=colors.HexColor("#4A4A6A"),
                spaceAfter=6,
            )

            story.append(Spacer(1, 3 * cm))
            story.append(Paragraph("🛡️ CSPM Security Report", title_style))
            story.append(Paragraph(title, subtitle_style))
            story.append(Spacer(1, 1 * cm))

            meta_data = [
                ["Generated:", datetime.now().strftime("%Y-%m-%d %H:%M UTC")],
                ["Scan Date:", str(scan.completed_at)[:19] if scan.completed_at else "N/A"],
                ["Provider:", getattr(scan, "cloud_account", {}) and "AWS" or "Cloud"],
                ["Risk Score:", f"{scan.risk_score or 0:.1f} / 100"],
                ["Resources Scanned:", str(scan.resources_scanned)],
                ["Total Findings:", str(scan.total_findings)],
            ]
            meta_table = Table(meta_data, colWidths=[4 * cm, 10 * cm])
            meta_table.setStyle(TableStyle([
                ("FONTSIZE", (0, 0), (-1, -1), 11),
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("TEXTCOLOR", (0, 0), (0, -1), colors.HexColor("#4A4A6A")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(meta_table)
            story.append(PageBreak())

            # ── Executive Summary ──────────────────────────────────────
            story.append(Paragraph("Executive Summary", styles["Heading1"]))
            story.append(HRFlowable(width="100%", thickness=1, color=colors.HexColor("#E0E0E0")))
            story.append(Spacer(1, 0.3 * cm))

            # Risk scorecard
            sev_counts = {
                "critical": scan.critical_findings,
                "high": scan.high_findings,
                "medium": scan.medium_findings,
                "low": scan.low_findings,
                "info": scan.info_findings,
            }
            scorecard_data = [["Severity", "Count", "Status"]]
            for sev in SEVERITY_ORDER:
                count = sev_counts.get(sev, 0)
                scorecard_data.append([
                    sev.title(),
                    str(count),
                    "⚠ Action Required" if count > 0 and sev in ("critical", "high") else ("Review" if count > 0 else "✓ Clean"),
                ])

            scorecard = Table(scorecard_data, colWidths=[5 * cm, 3 * cm, 8 * cm])
            sev_table_style = [
                ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1A1A2E")),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
                ("TOPPADDING", (0, 0), (-1, -1), 6),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
            ]
            # Color severity rows
            for i, sev in enumerate(SEVERITY_ORDER):
                r, g, b = SEVERITY_COLORS[sev]
                scorecard_data_row = i + 1
                sev_table_style.append(
                    ("TEXTCOLOR", (0, scorecard_data_row), (0, scorecard_data_row), colors.Color(r, g, b))
                )
                sev_table_style.append(
                    ("FONTNAME", (0, scorecard_data_row), (0, scorecard_data_row), "Helvetica-Bold")
                )
            scorecard.setStyle(TableStyle(sev_table_style))
            story.append(scorecard)
            story.append(Spacer(1, 0.5 * cm))

            # ── Findings by Severity ───────────────────────────────────
            for sev in SEVERITY_ORDER:
                sev_findings = [f for f in findings if f.severity == sev]
                if not sev_findings:
                    continue

                story.append(PageBreak())
                r, g, b = SEVERITY_COLORS[sev]
                sev_style = ParagraphStyle(
                    f"SevHead_{sev}",
                    parent=styles["Heading2"],
                    textColor=colors.Color(r, g, b),
                )
                story.append(Paragraph(f"{sev.upper()} Findings ({len(sev_findings)})", sev_style))
                story.append(HRFlowable(width="100%", thickness=1, color=colors.Color(r, g, b)))
                story.append(Spacer(1, 0.3 * cm))

                for i, f in enumerate(sev_findings[:50]):  # cap per severity
                    finding_block = []
                    finding_block.append(Paragraph(
                        f"<b>{i+1}. {f.rule_name}</b>",
                        ParagraphStyle("FindingTitle", parent=styles["Normal"], fontSize=10, spaceAfter=3),
                    ))

                    detail_data = [
                        [Paragraph("<b>Rule ID</b>", styles["Normal"]), f.rule_id],
                        [Paragraph("<b>Resource</b>", styles["Normal"]), f"{f.resource_type}: {f.resource_name or f.resource_id}"],
                        [Paragraph("<b>Region</b>", styles["Normal"]), f.region or "Global"],
                        [Paragraph("<b>CVSS Score</b>", styles["Normal"]), str(f.cvss_score or "N/A")],
                    ]
                    if f.cis_benchmark_refs:
                        detail_data.append([Paragraph("<b>CIS Refs</b>", styles["Normal"]), ", ".join(f.cis_benchmark_refs)])
                    if f.remediation_steps:
                        detail_data.append([Paragraph("<b>Remediation</b>", styles["Normal"]), Paragraph(f.remediation_steps[:400], styles["Normal"])])
                    if f.ai_explanation:
                        detail_data.append([Paragraph("<b>AI Analysis</b>", styles["Normal"]), Paragraph(f.ai_explanation[:400], styles["Normal"])])

                    detail_table = Table(detail_data, colWidths=[3.5 * cm, 12.5 * cm])
                    detail_table.setStyle(TableStyle([
                        ("FONTSIZE", (0, 0), (-1, -1), 9),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#FAFAFA")),
                        ("BOX", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 0), (-1, -1), 4),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ]))
                    finding_block.append(detail_table)
                    finding_block.append(Spacer(1, 0.4 * cm))
                    story.append(KeepTogether(finding_block))

            # ── Footer page ───────────────────────────────────────────
            story.append(PageBreak())
            story.append(Paragraph("Report generated by CSPM Platform", styles["Normal"]))

            doc.build(story)
            buffer.seek(0)
            return buffer.read()

        except Exception as exc:
            logger.error(f"PDF build failed: {exc}")
            raise
