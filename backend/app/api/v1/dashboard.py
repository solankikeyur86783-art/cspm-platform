from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any

from fastapi import APIRouter
from sqlalchemy import select, func, desc

from app.api.deps import CurrentUser, DB
from app.models.finding import Finding, Severity
from app.models.scan import Scan, ScanStatus
from app.models.cloud_account import CloudAccount

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])


@router.get("/summary")
async def get_summary(current_user: CurrentUser, db: DB) -> Dict[str, Any]:
    """Overall posture summary for the current user."""

    # Total accounts
    accounts_count = (
        await db.execute(
            select(func.count(CloudAccount.id)).where(CloudAccount.owner_id == current_user.id)
        )
    ).scalar_one()

    # Total scans
    scans_result = await db.execute(
        select(func.count(Scan.id), func.avg(Scan.risk_score))
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(
            CloudAccount.owner_id == current_user.id,
            Scan.status == ScanStatus.COMPLETED,
        )
    )
    scans_row = scans_result.one()
    total_scans = scans_row[0] or 0
    avg_risk_score = round(float(scans_row[1] or 0), 1)

    # Findings by severity (all open findings)
    sev_rows = (
        await db.execute(
            select(Finding.severity, func.count(Finding.id))
            .join(Scan, Finding.scan_id == Scan.id)
            .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
            .where(
                CloudAccount.owner_id == current_user.id,
                Finding.is_suppressed == False,
                Finding.status == "open",
            )
            .group_by(Finding.severity)
        )
    ).all()
    severity_counts = {row[0]: row[1] for row in sev_rows}
    total_open = sum(severity_counts.values())

    # Most recent scan per account
    latest_scan = (
        await db.execute(
            select(Scan)
            .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
            .where(
                CloudAccount.owner_id == current_user.id,
                Scan.status == ScanStatus.COMPLETED,
            )
            .order_by(desc(Scan.completed_at))
            .limit(1)
        )
    ).scalar_one_or_none()

    return {
        "cloud_accounts": accounts_count,
        "total_scans": total_scans,
        "average_risk_score": avg_risk_score,
        "total_open_findings": total_open,
        "findings_by_severity": {
            "critical": severity_counts.get(Severity.CRITICAL, 0),
            "high": severity_counts.get(Severity.HIGH, 0),
            "medium": severity_counts.get(Severity.MEDIUM, 0),
            "low": severity_counts.get(Severity.LOW, 0),
            "info": severity_counts.get(Severity.INFO, 0),
        },
        "last_scan_at": latest_scan.completed_at.isoformat() if latest_scan else None,
        "last_risk_score": latest_scan.risk_score if latest_scan else None,
    }


@router.get("/risk-trend")
async def get_risk_trend(
    current_user: CurrentUser,
    db: DB,
    days: int = 30,
) -> List[Dict[str, Any]]:
    """Risk score trend over the last N days."""
    since = datetime.now(timezone.utc) - timedelta(days=days)

    rows = (
        await db.execute(
            select(
                func.date(Scan.completed_at).label("date"),
                func.avg(Scan.risk_score).label("avg_score"),
                func.sum(Scan.total_findings).label("total_findings"),
            )
            .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
            .where(
                CloudAccount.owner_id == current_user.id,
                Scan.status == ScanStatus.COMPLETED,
                Scan.completed_at >= since,
            )
            .group_by(func.date(Scan.completed_at))
            .order_by(func.date(Scan.completed_at))
        )
    ).all()

    return [
        {
            "date": str(row.date),
            "risk_score": round(float(row.avg_score or 0), 1),
            "total_findings": int(row.total_findings or 0),
        }
        for row in rows
    ]


@router.get("/top-risks")
async def get_top_risks(current_user: CurrentUser, db: DB, limit: int = 10) -> List[Dict]:
    """Top recurring rules by finding count."""
    rows = (
        await db.execute(
            select(
                Finding.rule_id,
                Finding.rule_name,
                Finding.severity,
                func.count(Finding.id).label("count"),
            )
            .join(Scan, Finding.scan_id == Scan.id)
            .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
            .where(
                CloudAccount.owner_id == current_user.id,
                Finding.is_suppressed == False,
                Finding.status == "open",
            )
            .group_by(Finding.rule_id, Finding.rule_name, Finding.severity)
            .order_by(desc("count"))
            .limit(limit)
        )
    ).all()

    return [
        {
            "rule_id": row.rule_id,
            "rule_name": row.rule_name,
            "severity": row.severity,
            "count": row.count,
        }
        for row in rows
    ]


@router.get("/compliance")
async def get_compliance_posture(current_user: CurrentUser, db: DB) -> Dict[str, Any]:
    """Compliance framework posture — percentage of passing controls."""
    from app.rules.compliance_mapper import calculate_compliance_posture

    rows = (
        await db.execute(
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
            .where(
                CloudAccount.owner_id == current_user.id,
                Finding.is_suppressed == False,
                Finding.status == "open",
            )
        )
    ).scalars().all()

    return calculate_compliance_posture(rows)
