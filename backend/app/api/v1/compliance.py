import uuid
from typing import Dict, Any, List

from fastapi import APIRouter
from sqlalchemy import select

from app.api.deps import CurrentUser, DB
from app.models.finding import Finding
from app.models.scan import Scan
from app.models.cloud_account import CloudAccount
from app.rules.compliance_mapper import (
    FRAMEWORK_CONTROLS,
    calculate_compliance_posture,
    map_to_compliance_frameworks,
)

router = APIRouter(prefix="/compliance", tags=["Compliance"])


@router.get("/frameworks")
async def list_frameworks() -> List[str]:
    """List all supported compliance frameworks."""
    return list(FRAMEWORK_CONTROLS.keys())


@router.get("/posture")
async def get_compliance_posture(
    current_user: CurrentUser,
    db: DB,
    scan_id: uuid.UUID | None = None,
) -> Dict[str, Any]:
    """
    Get compliance posture across all frameworks.
    Optionally scoped to a specific scan.
    """
    query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(
            CloudAccount.owner_id == current_user.id,
            Finding.is_suppressed == False,
            Finding.status == "open",
        )
    )
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)

    findings = (await db.execute(query)).scalars().all()
    posture = calculate_compliance_posture(findings)

    return {
        "posture": posture,
        "total_open_findings": len(findings),
        "scoped_to_scan": str(scan_id) if scan_id else None,
    }


@router.get("/posture/{framework}")
async def get_framework_posture(
    framework: str,
    current_user: CurrentUser,
    db: DB,
    scan_id: uuid.UUID | None = None,
) -> Dict[str, Any]:
    """Get detailed posture for a specific framework with control-level breakdown."""
    if framework not in FRAMEWORK_CONTROLS:
        from fastapi import HTTPException, status
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Framework '{framework}' not found. Available: {list(FRAMEWORK_CONTROLS.keys())}",
        )

    query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(
            CloudAccount.owner_id == current_user.id,
            Finding.is_suppressed == False,
            Finding.status == "open",
        )
    )
    if scan_id:
        query = query.where(Finding.scan_id == scan_id)

    findings = (await db.execute(query)).scalars().all()

    # Build control-level breakdown
    controls = FRAMEWORK_CONTROLS[framework]
    control_breakdown = []

    for control_name, rule_prefixes in controls.items():
        control_findings = [
            f for f in findings
            if any(f.rule_id.startswith(prefix) for prefix in rule_prefixes)
        ]
        control_breakdown.append({
            "control": control_name,
            "status": "failing" if control_findings else "passing",
            "finding_count": len(control_findings),
            "severity_breakdown": {
                sev: sum(1 for f in control_findings if f.severity == sev)
                for sev in ("critical", "high", "medium", "low", "info")
            },
            "top_findings": [
                {
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "severity": f.severity,
                    "resource": f.resource_name or f.resource_id,
                }
                for f in sorted(control_findings, key=lambda x: x.cvss_score or 0, reverse=True)[:3]
            ],
        })

    passing = sum(1 for c in control_breakdown if c["status"] == "passing")
    total = len(control_breakdown)

    return {
        "framework": framework,
        "score_percent": round((passing / total) * 100, 1) if total else 100.0,
        "passing_controls": passing,
        "failing_controls": total - passing,
        "total_controls": total,
        "controls": control_breakdown,
    }


@router.get("/finding/{finding_id}/frameworks")
async def get_finding_frameworks(
    finding_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
) -> Dict[str, Any]:
    """Get compliance framework mappings for a specific finding."""
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(Finding.id == finding_id, CloudAccount.owner_id == current_user.id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        from app.core.exceptions import http_not_found
        raise http_not_found("Finding", str(finding_id))

    frameworks = map_to_compliance_frameworks(finding.rule_id)
    return {
        "finding_id": str(finding_id),
        "rule_id": finding.rule_id,
        "frameworks": frameworks,
        "cis_refs": finding.cis_benchmark_refs or [],
        "mitre_techniques": finding.mitre_attack_techniques or [],
    }
