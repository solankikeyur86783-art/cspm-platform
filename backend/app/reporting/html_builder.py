import os
from datetime import datetime, timezone
from typing import Any, Dict, List
from jinja2 import Environment, FileSystemLoader

from app.core.logging import logger

TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "templates")


class HTMLReportBuilder:
    def __init__(self):
        self.env = Environment(loader=FileSystemLoader(TEMPLATES_DIR))

    def build(
        self,
        scan,
        findings: list,
        title: str,
        executive_summary: str = "",
    ) -> bytes:
        template = self.env.get_template("scan_report.html")

        html = template.render(
            title=title,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            scan_date=str(scan.completed_at)[:19] if scan.completed_at else "N/A",
            resources_scanned=scan.resources_scanned,
            risk_score=scan.risk_score or 0,
            critical_count=scan.critical_findings,
            high_count=scan.high_findings,
            medium_count=scan.medium_findings,
            low_count=scan.low_findings,
            info_count=scan.info_findings,
            findings=findings,
            executive_summary=executive_summary,
        )
        return html.encode("utf-8")
