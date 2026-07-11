import uuid
from typing import List, Dict, Any

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select

from app.api.deps import AnalystUser, CurrentUser, DB
from app.core.exceptions import http_not_found
from app.models.finding import Finding, FindingStatus
from app.models.scan import Scan
from app.models.cloud_account import CloudAccount

router = APIRouter(prefix="/remediation", tags=["Remediation"])

# Rules that support automatic remediation
AUTO_REMEDIABLE_RULES = {
    "CIS-S3-2.1.1": "Block S3 bucket public access",
    "CIS-EC2-2.2.1": "Enable EBS encryption by default",
    "EC2-IMDS-001": "Enforce IMDSv2 on EC2 instance",
    "CIS-RDS-2.3.2": "Disable RDS public accessibility",
}


class RemediationRequest(BaseModel):
    finding_ids: List[uuid.UUID]
    dry_run: bool = True  # Safety default: preview only


class RemediationResult(BaseModel):
    finding_id: str
    rule_id: str
    resource_id: str
    auto_remediable: bool
    dry_run: bool
    action: str
    status: str
    error: str | None = None


@router.get("/supported-rules")
async def get_supported_rules() -> Dict[str, str]:
    """List all rules that support automatic remediation."""
    return AUTO_REMEDIABLE_RULES


@router.post("/execute", response_model=List[RemediationResult])
async def execute_remediation(
    payload: RemediationRequest,
    current_user: AnalystUser,
    db: DB,
) -> List[RemediationResult]:
    """
    Trigger auto-remediation for selected findings.
    Defaults to dry_run=True for safety — set dry_run=False to actually remediate.
    """
    results = []

    for finding_id in payload.finding_ids:
        # Verify ownership
        result = await db.execute(
            select(Finding)
            .join(Scan, Finding.scan_id == Scan.id)
            .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
            .where(
                Finding.id == finding_id,
                CloudAccount.owner_id == current_user.id,
            )
        )
        finding: Finding | None = result.scalar_one_or_none()

        if not finding:
            results.append(RemediationResult(
                finding_id=str(finding_id),
                rule_id="unknown",
                resource_id="unknown",
                auto_remediable=False,
                dry_run=payload.dry_run,
                action="Skipped — finding not found or not owned by user",
                status="skipped",
            ))
            continue

        is_remediable = finding.rule_id in AUTO_REMEDIABLE_RULES
        action = AUTO_REMEDIABLE_RULES.get(finding.rule_id, "No automatic remediation available")

        if not is_remediable:
            results.append(RemediationResult(
                finding_id=str(finding_id),
                rule_id=finding.rule_id,
                resource_id=finding.resource_id,
                auto_remediable=False,
                dry_run=payload.dry_run,
                action="Manual remediation required",
                status="not_supported",
            ))
            continue

        if payload.dry_run:
            results.append(RemediationResult(
                finding_id=str(finding_id),
                rule_id=finding.rule_id,
                resource_id=finding.resource_id,
                auto_remediable=True,
                dry_run=True,
                action=f"[DRY RUN] Would execute: {action}",
                status="dry_run_ok",
            ))
            continue

        # Execute actual remediation via Celery
        try:
            from app.workers.remediation_tasks import auto_remediate
            task = auto_remediate.delay(str(finding_id), str(current_user.id))

            results.append(RemediationResult(
                finding_id=str(finding_id),
                rule_id=finding.rule_id,
                resource_id=finding.resource_id,
                auto_remediable=True,
                dry_run=False,
                action=action,
                status="queued",
            ))
        except Exception as exc:
            results.append(RemediationResult(
                finding_id=str(finding_id),
                rule_id=finding.rule_id,
                resource_id=finding.resource_id,
                auto_remediable=True,
                dry_run=False,
                action=action,
                status="failed",
                error=str(exc),
            ))

    return results


@router.get("/finding/{finding_id}/steps")
async def get_remediation_steps(
    finding_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
) -> Dict[str, Any]:
    """Get detailed remediation steps for a finding, including AI-generated guidance."""
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(Finding.id == finding_id, CloudAccount.owner_id == current_user.id)
    )
    finding: Finding | None = result.scalar_one_or_none()
    if not finding:
        raise http_not_found("Finding", str(finding_id))

    return {
        "finding_id": str(finding_id),
        "rule_id": finding.rule_id,
        "rule_name": finding.rule_name,
        "severity": finding.severity,
        "resource_id": finding.resource_id,
        "resource_type": finding.resource_type,
        "auto_remediable": finding.rule_id in AUTO_REMEDIABLE_RULES,
        "remediation_steps": finding.remediation_steps,
        "remediation_code": finding.remediation_code,
        "ai_explanation": finding.ai_explanation,
        "ai_remediation": finding.ai_remediation,
        "mitre_attack_techniques": finding.mitre_attack_techniques or [],
        "cis_refs": finding.cis_benchmark_refs or [],
    }


@router.post("/finding/{finding_id}/ai-remediation")
async def get_ai_remediation(
    finding_id: uuid.UUID,
    current_user: CurrentUser,
    db: DB,
) -> Dict[str, str]:
    """Generate fresh AI remediation guidance for a finding using Groq."""
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(Finding.id == finding_id, CloudAccount.owner_id == current_user.id)
    )
    finding: Finding | None = result.scalar_one_or_none()
    if not finding:
        raise http_not_found("Finding", str(finding_id))

    from app.ai.groq_client import GroqClient
    from app.ai.risk_explainer import RiskExplainer
    from app.scanners.base import ScanFinding

    # Convert DB model to ScanFinding for explainer
    scan_finding = ScanFinding(
        rule_id=finding.rule_id,
        rule_name=finding.rule_name,
        rule_description=finding.rule_description or "",
        severity=finding.severity,
        resource_id=finding.resource_id,
        resource_type=finding.resource_type,
        cloud_provider=finding.cloud_provider,
        cvss_score=finding.cvss_score,
        evidence=finding.evidence or {},
        cis_benchmark_refs=finding.cis_benchmark_refs or [],
        mitre_attack_techniques=finding.mitre_attack_techniques or [],
        remediation_steps=finding.remediation_steps or "",
    )

    client = GroqClient()
    explainer = RiskExplainer(client)
    ai_result = await explainer.explain(scan_finding)

    # Persist the AI result
    if ai_result:
        finding.ai_explanation = ai_result.get("explanation")
        finding.ai_remediation = ai_result.get("remediation")
        db.add(finding)

    return {
        "explanation": ai_result.get("explanation", ""),
        "remediation": ai_result.get("remediation", ""),
        "attack_scenario": ai_result.get("attack_scenario", ""),
        "priority": ai_result.get("priority", "medium"),
    }
