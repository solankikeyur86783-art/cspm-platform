"""
app/core/alerts.py — Discord + Email alert system.
Called automatically at end of every scan when critical/high findings exist.

Configure in .env:
  DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
  SMTP_HOST=smtp.gmail.com
  SMTP_PORT=587
  SMTP_USER=you@gmail.com
  SMTP_PASSWORD=your-app-password
  ALERT_EMAIL=security@yourcompany.com
  ALERT_MIN_SEVERITY=high   # only alert on high+critical (options: critical/high/medium)
"""

import asyncio
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from datetime import datetime, timezone
from typing import List, Any, Dict

import httpx

from app.core.logging import logger

# ── Severity config ───────────────────────────────────────────────────────────
SEVERITY_EMOJI  = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}
SEVERITY_COLOR  = {"critical": 0xC53030, "high": 0xC05621, "medium": 0xB7791F, "low": 0x276749}
SEVERITY_RANK   = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _get_settings():
    from app.core.config import settings
    return settings


def _should_alert(severity: str, min_severity: str = "high") -> bool:
    return SEVERITY_RANK.get(severity, 0) >= SEVERITY_RANK.get(min_severity, 3)


# ── Discord ───────────────────────────────────────────────────────────────────

async def _send_discord(summary: Dict, findings: List) -> None:
    settings = _get_settings()
    webhook  = getattr(settings, "DISCORD_WEBHOOK_URL", "")
    if not webhook:
        return

    risk   = summary.get("risk_score", 0)
    color  = SEVERITY_COLOR["critical"] if risk >= 70 else SEVERITY_COLOR["medium"]

    # Top findings list
    top_lines = []
    for f in findings[:5]:
        sev  = getattr(f, "severity", "info")
        name = getattr(f, "rule_name", str(f))[:55]
        res  = (getattr(f, "resource_name", "") or getattr(f, "resource_id", ""))[:35]
        top_lines.append(f"{SEVERITY_EMOJI[sev]} `{name}`\n  ↳ {res}")

    payload = {
        "username": "CSPM Platform 🛡️",
        "embeds": [{
            "title": f"Scan Complete — {summary.get('account_name', 'Cloud Account')}",
            "url": f"{getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')}/scans/{summary.get('scan_id', '')}",
            "color": color,
            "description": (
                f"**Provider:** {summary.get('provider','').upper()}  |  "
                f"**Resources:** {summary.get('resources_scanned', 0)}  |  "
                f"**Duration:** {summary.get('duration_seconds', 0)}s  |  "
                f"**Risk Score:** {risk}/100"
            ),
            "fields": [
                {
                    "name": "📊 Severity Breakdown",
                    "value": (
                        f"{SEVERITY_EMOJI['critical']} Critical: **{summary.get('critical_findings',0)}**\n"
                        f"{SEVERITY_EMOJI['high']}     High:     **{summary.get('high_findings',0)}**\n"
                        f"{SEVERITY_EMOJI['medium']}    Medium:   **{summary.get('medium_findings',0)}**\n"
                        f"{SEVERITY_EMOJI['low']}     Low:      **{summary.get('low_findings',0)}**"
                    ),
                    "inline": True,
                },
                {
                    "name": f"🚨 Top Findings ({len(findings)} critical/high)",
                    "value": "\n".join(top_lines) if top_lines else "None",
                    "inline": False,
                },
            ],
            "footer": {
                "text": f"CSPM Platform  •  {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}"
            },
        }],
    }

    try:
        async with httpx.AsyncClient(timeout=10) as client:
            r = await client.post(webhook, json=payload)
            r.raise_for_status()
        logger.info("✅  Discord alert sent")
    except Exception as exc:
        logger.warning(f"Discord alert failed: {exc}")


# ── Email ─────────────────────────────────────────────────────────────────────

async def _send_email(summary: Dict, findings: List) -> None:
    settings     = _get_settings()
    smtp_host    = getattr(settings, "SMTP_HOST", "")
    smtp_port    = int(getattr(settings, "SMTP_PORT", 587))
    smtp_user    = getattr(settings, "SMTP_USER", "")
    smtp_pass    = getattr(settings, "SMTP_PASSWORD", "")
    alert_email  = getattr(settings, "ALERT_EMAIL", "")

    if not all([smtp_host, smtp_user, smtp_pass, alert_email]):
        return

    risk         = summary.get("risk_score", 0)
    account      = summary.get("account_name", "Cloud Account")
    scan_date    = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    scan_url     = f"{getattr(settings, 'FRONTEND_URL', 'http://localhost:3000')}/scans/{summary.get('scan_id', '')}"
    subject      = (
        f"[CSPM] ⚠️ {account} — Risk {risk}/100 — "
        f"{summary.get('critical_findings',0)} Critical  "
        f"{summary.get('high_findings',0)} High"
    )

    # Finding rows for HTML table
    rows = ""
    for f in findings[:15]:
        sev   = getattr(f, "severity", "")
        name  = getattr(f, "rule_name", str(f))
        res   = (getattr(f, "resource_name", "") or getattr(f, "resource_id", ""))[:50]
        rule  = getattr(f, "rule_id", "")
        cvss  = getattr(f, "cvss_score", "")
        bg    = {"critical":"#C53030","high":"#C05621","medium":"#B7791F"}.get(sev, "#276749")
        rows += f"""
        <tr>
          <td style="padding:8px 12px;border-bottom:1px solid #EDF2F7;">
            <span style="background:{bg};color:#fff;padding:2px 8px;border-radius:4px;
                         font-size:11px;font-weight:600;text-transform:uppercase;">{sev}</span>
          </td>
          <td style="padding:8px 12px;border-bottom:1px solid #EDF2F7;font-family:monospace;font-size:12px;color:#4A5568;">{rule}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #EDF2F7;font-size:13px;">{name}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #EDF2F7;font-size:12px;color:#718096;">{res}</td>
          <td style="padding:8px 12px;border-bottom:1px solid #EDF2F7;font-size:12px;color:#718096;">{cvss}</td>
        </tr>"""

    html = f"""<!DOCTYPE html><html><body style="font-family:-apple-system,sans-serif;background:#F5F7FA;margin:0;padding:24px;">
<div style="max-width:720px;margin:0 auto;background:#fff;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.1);overflow:hidden;">
  <div style="background:#1A1A2E;color:#fff;padding:28px 32px;">
    <h1 style="margin:0;font-size:22px;font-weight:600;">🛡️ CSPM Security Scan Report</h1>
    <p style="margin:8px 0 0;opacity:.65;font-size:13px;">{account} &nbsp;•&nbsp; {scan_date}</p>
  </div>
  <div style="padding:28px 32px;">
    <!-- Scorecard -->
    <table style="width:100%;border-collapse:separate;border-spacing:8px;margin-bottom:24px;">
      <tr>
        <td style="text-align:center;padding:16px;background:#FFF5F5;border-radius:8px;">
          <div style="font-size:32px;font-weight:700;color:#C53030;">{summary.get('critical_findings',0)}</div>
          <div style="font-size:11px;color:#718096;text-transform:uppercase;letter-spacing:.05em;margin-top:4px;">Critical</div>
        </td>
        <td style="text-align:center;padding:16px;background:#FFFAF0;border-radius:8px;">
          <div style="font-size:32px;font-weight:700;color:#C05621;">{summary.get('high_findings',0)}</div>
          <div style="font-size:11px;color:#718096;text-transform:uppercase;letter-spacing:.05em;margin-top:4px;">High</div>
        </td>
        <td style="text-align:center;padding:16px;background:#FFFFF0;border-radius:8px;">
          <div style="font-size:32px;font-weight:700;color:#B7791F;">{summary.get('medium_findings',0)}</div>
          <div style="font-size:11px;color:#718096;text-transform:uppercase;letter-spacing:.05em;margin-top:4px;">Medium</div>
        </td>
        <td style="text-align:center;padding:16px;background:#F0FFF4;border-radius:8px;">
          <div style="font-size:32px;font-weight:700;color:#276749;">{summary.get('low_findings',0)}</div>
          <div style="font-size:11px;color:#718096;text-transform:uppercase;letter-spacing:.05em;margin-top:4px;">Low</div>
        </td>
        <td style="text-align:center;padding:16px;background:#EBF8FF;border-radius:8px;">
          <div style="font-size:32px;font-weight:700;color:#2B6CB0;">{risk}</div>
          <div style="font-size:11px;color:#718096;text-transform:uppercase;letter-spacing:.05em;margin-top:4px;">Risk /100</div>
        </td>
      </tr>
    </table>

    <!-- Findings table -->
    {"<h3 style='font-size:15px;margin:0 0 12px;color:#1A1A2E;'>🚨 Critical & High Findings</h3>" if rows else ""}
    {f'''<table style="width:100%;border-collapse:collapse;font-size:13px;">
      <thead>
        <tr style="background:#F7FAFC;">
          <th style="padding:10px 12px;text-align:left;font-size:11px;color:#718096;text-transform:uppercase;letter-spacing:.05em;">Severity</th>
          <th style="padding:10px 12px;text-align:left;font-size:11px;color:#718096;text-transform:uppercase;letter-spacing:.05em;">Rule</th>
          <th style="padding:10px 12px;text-align:left;font-size:11px;color:#718096;text-transform:uppercase;letter-spacing:.05em;">Finding</th>
          <th style="padding:10px 12px;text-align:left;font-size:11px;color:#718096;text-transform:uppercase;letter-spacing:.05em;">Resource</th>
          <th style="padding:10px 12px;text-align:left;font-size:11px;color:#718096;text-transform:uppercase;letter-spacing:.05em;">CVSS</th>
        </tr>
      </thead>
      <tbody>{rows}</tbody>
    </table>''' if rows else ''}

    <!-- CTA -->
    <div style="text-align:center;margin-top:28px;">
      <a href="{scan_url}" style="display:inline-block;background:#1A1A2E;color:#fff;padding:12px 28px;
         border-radius:8px;text-decoration:none;font-size:14px;font-weight:500;">
        View Full Report →
      </a>
    </div>
  </div>
  <div style="padding:16px 32px;background:#F7FAFC;border-top:1px solid #EDF2F7;text-align:center;font-size:12px;color:#A0AEC0;">
    CSPM Platform &nbsp;•&nbsp; {scan_date}
  </div>
</div>
</body></html>"""

    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = smtp_user
    msg["To"]      = alert_email
    msg.attach(MIMEText(html, "html"))

    try:
        def _send():
            with smtplib.SMTP(smtp_host, smtp_port) as srv:
                srv.ehlo()
                srv.starttls()
                srv.login(smtp_user, smtp_pass)
                srv.send_message(msg)

        await asyncio.get_event_loop().run_in_executor(None, _send)
        logger.info(f"✅  Email alert sent → {alert_email}")
    except Exception as exc:
        logger.warning(f"Email alert failed: {exc}")


# ── Public entry point ────────────────────────────────────────────────────────

async def send_scan_alerts(scan, findings: List[Any]) -> None:
    """
    Call this at the END of _execute_scan() in workers/scan_tasks.py:

        from app.core.alerts import send_scan_alerts
        await send_scan_alerts(scan, enriched_findings)
    """
    settings    = _get_settings()
    min_sev     = getattr(settings, "ALERT_MIN_SEVERITY", "high")
    alert_list  = [f for f in findings if _should_alert(getattr(f, "severity", ""), min_sev)]

    if not alert_list:
        logger.debug(f"No {min_sev}+ findings — skipping alerts")
        return

    # Build summary dict from scan ORM object
    summary = {
        "scan_id":           str(scan.id),
        "account_name":      "Cloud Account",
        "provider":          "aws",
        "risk_score":        round(scan.risk_score or 0, 1),
        "resources_scanned": scan.resources_scanned,
        "duration_seconds":  scan.duration_seconds,
        "total_findings":    scan.total_findings,
        "critical_findings": scan.critical_findings,
        "high_findings":     scan.high_findings,
        "medium_findings":   scan.medium_findings,
        "low_findings":      scan.low_findings,
    }

    logger.info(f"Sending alerts for {len(alert_list)} {min_sev}+ findings")
    await asyncio.gather(
        _send_discord(summary, alert_list),
        _send_email(summary, alert_list),
        return_exceptions=True,
    )
