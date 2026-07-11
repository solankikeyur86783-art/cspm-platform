import asyncio
import uuid
from datetime import datetime, timezone
from typing import List

from celery import Task
from celery.utils.log import get_task_logger

from app.workers.celery_app import celery_app
from app.core.config import settings

logger = get_task_logger(__name__)


class ScanTask(Task):
    abstract = True

    def on_failure(self, exc, task_id, args, kwargs, einfo):
        scan_id = args[0] if args else None
        if scan_id:
            asyncio.run(_mark_scan_failed(scan_id, str(exc)))
        logger.error(f"Scan task {task_id} failed: {exc}")


@celery_app.task(bind=True, base=ScanTask, name="app.workers.scan_tasks.run_scan")
def run_scan(self, scan_id: str, account_id: str):
    """Main scan orchestration task."""
    logger.info(f"Starting scan {scan_id} for account {account_id}")
    asyncio.run(_execute_scan(scan_id, account_id, self))


async def _execute_scan(scan_id: str, account_id: str, task) -> None:
    from app.core.database import AsyncSessionLocal
    from app.core.redis_client import cache
    from app.models.scan import Scan, ScanStatus
    from app.models.cloud_account import CloudAccount
    from app.models.finding import Finding
    from app.rules.compliance_mapper import (
        calculate_risk_score, map_to_compliance_frameworks, enrich_cvss
    )
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        # Load scan and account
        scan_result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
        scan: Scan = scan_result.scalar_one_or_none()
        if not scan:
            logger.error(f"Scan {scan_id} not found")
            return

        account_result = await db.execute(select(CloudAccount).where(CloudAccount.id == uuid.UUID(account_id)))
        account: CloudAccount = account_result.scalar_one_or_none()
        if not account:
            await _mark_scan_failed(scan_id, "Cloud account not found")
            return

        # Mark as running
        scan.status = ScanStatus.RUNNING
        scan.started_at = datetime.now(timezone.utc)
        scan.progress = 5
        db.add(scan)
        await db.commit()

        await cache.set_scan_status(scan_id, {"status": "running", "progress": 5, "message": "Initializing scanners"})

        # Build account config dict for scanners
        account_config = {
            "provider": account.provider,
            "aws_regions": account.aws_regions or ["us-east-1"],
            "gcp_project_id": account.gcp_project_id,
            "azure_subscription_id": account.azure_subscription_id,
            "region": (account.aws_regions or ["us-east-1"])[0],
        }

        # Select scanners based on provider
        scanners = _get_scanners(account.provider, account_config)
        if not scanners:
            await _mark_scan_failed(scan_id, f"No scanners available for provider: {account.provider}")
            return

        all_findings = []
        total_resources = 0
        errors = []
        progress_step = 80 // len(scanners)

        for i, scanner_cls in enumerate(scanners):
            scanner_name = f"{scanner_cls.provider}/{scanner_cls.service}"
            logger.info(f"Running scanner: {scanner_name}")
            await cache.set_scan_status(scan_id, {
                "status": "running",
                "progress": 10 + (i * progress_step),
                "message": f"Scanning {scanner_name}...",
            })

            try:
                scanner = scanner_cls(account_config)
                result = await scanner.scan()
                all_findings.extend(result.findings)
                total_resources += result.resources_scanned
                errors.extend(result.errors)
                logger.info(f"Scanner {scanner_name}: {len(result.findings)} findings, {result.resources_scanned} resources")
            except Exception as exc:
                logger.error(f"Scanner {scanner_name} crashed: {exc}")
                errors.append(f"{scanner_name}: {str(exc)}")

        # Enrich findings
        logger.info(f"Enriching {len(all_findings)} findings")
        await cache.set_scan_status(scan_id, {"status": "running", "progress": 90, "message": "Enriching findings with AI..."})

        enriched_findings = []
        for f in all_findings:
            f = enrich_cvss(f)
            f.compliance_frameworks = map_to_compliance_frameworks(f.rule_id)
            enriched_findings.append(f)

        # Batch AI enrichment (optional, can be slow)
        if scan.scan_config and scan.scan_config.get("include_ai_analysis", True):
            try:
                enriched_findings = await _ai_enrich_findings(enriched_findings[:50])  # limit for speed
            except Exception as exc:
                logger.warning(f"AI enrichment failed (non-fatal): {exc}")

        # Persist findings
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        db_findings = []

        for f in enriched_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1
            db_finding = Finding(
                scan_id=scan.id,
                rule_id=f.rule_id,
                rule_name=f.rule_name,
                rule_description=f.rule_description,
                severity=f.severity,
                cvss_score=f.cvss_score,
                cvss_vector=f.cvss_vector,
                resource_id=f.resource_id,
                resource_type=f.resource_type,
                resource_name=f.resource_name,
                resource_arn=f.resource_arn,
                region=f.region,
                cloud_provider=f.cloud_provider,
                evidence=f.evidence,
                cis_benchmark_refs=f.cis_benchmark_refs,
                mitre_attack_techniques=f.mitre_attack_techniques,
                compliance_frameworks=f.compliance_frameworks,
                remediation_steps=f.remediation_steps,
                remediation_code=f.remediation_code,
                ai_explanation=getattr(f, "ai_explanation", None),
                ai_remediation=getattr(f, "ai_remediation", None),
            )
            db_findings.append(db_finding)

        db.add_all(db_findings)

        # Update scan record
        risk_score = calculate_risk_score(enriched_findings)
        scan.status = ScanStatus.COMPLETED
        scan.completed_at = datetime.now(timezone.utc)
        scan.duration_seconds = int((scan.completed_at - scan.started_at).total_seconds())
        scan.total_findings = len(enriched_findings)
        scan.critical_findings = severity_counts.get("critical", 0)
        scan.high_findings = severity_counts.get("high", 0)
        scan.medium_findings = severity_counts.get("medium", 0)
        scan.low_findings = severity_counts.get("low", 0)
        scan.info_findings = severity_counts.get("info", 0)
        scan.risk_score = risk_score
        scan.resources_scanned = total_resources
        scan.progress = 100
        scan.services_scanned = [f"{s.provider}/{s.service}" for s in [scanner_cls(account_config) for scanner_cls in scanners]]
        if errors:
            scan.error_message = f"Completed with {len(errors)} scanner errors. First: {errors[0]}"

        db.add(scan)

        # Update account
        account.scan_count = (account.scan_count or 0) + 1
        account.last_scanned_at = scan.completed_at.isoformat()
        db.add(account)

        await db.commit()

        await cache.set_scan_status(scan_id, {
            "status": "completed",
            "progress": 100,
            "total_findings": len(enriched_findings),
            "risk_score": risk_score,
        })

        logger.info(
            f"Scan {scan_id} completed: {len(enriched_findings)} findings, "
            f"risk_score={risk_score}, duration={scan.duration_seconds}s"
        )

        # ── Send Discord + Email alerts for critical/high findings ────
        try:
            from app.core.alerts import send_scan_alerts
            await send_scan_alerts(scan, enriched_findings)
        except Exception as exc:
            logger.warning(f"Alert sending failed (non-fatal): {exc}")


def _get_scanners(provider: str, account_config: dict) -> list:
    if provider == "aws":
        from app.scanners.aws import AWS_SCANNERS
        return AWS_SCANNERS
    elif provider == "gcp":
        from app.scanners.gcp import GCP_SCANNERS
        return GCP_SCANNERS
    elif provider == "azure":
        from app.scanners.azure import AZURE_SCANNERS
        return AZURE_SCANNERS
    return []


async def _mark_scan_failed(scan_id: str, error: str) -> None:
    from app.core.database import AsyncSessionLocal
    from app.models.scan import Scan, ScanStatus
    from app.core.redis_client import cache
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Scan).where(Scan.id == uuid.UUID(scan_id)))
        scan = result.scalar_one_or_none()
        if scan:
            scan.status = ScanStatus.FAILED
            scan.error_message = error
            scan.completed_at = datetime.now(timezone.utc)
            db.add(scan)
            await db.commit()

    await cache.set_scan_status(scan_id, {"status": "failed", "error": error})


async def _ai_enrich_findings(findings: list) -> list:
    """Enrich top critical/high findings with AI explanations."""
    from app.ai.groq_client import GroqClient
    from app.ai.risk_explainer import RiskExplainer

    client = GroqClient()
    explainer = RiskExplainer(client)

    priority = [f for f in findings if f.severity in ("critical", "high")][:20]

    for finding in priority:
        try:
            explanation = await explainer.explain(finding)
            finding.ai_explanation = explanation.get("explanation")
            finding.ai_remediation = explanation.get("remediation")
        except Exception:
            pass

    return findings


# ── Scheduled scan task — called by Celery Beat every 30 min ─────────────────

@celery_app.task(name="app.workers.scan_tasks.scan_all_active_accounts")
def scan_all_active_accounts(config: dict = None):
    """
    Triggered by Celery Beat on a schedule.
    Scans every active + valid cloud account automatically.
    """
    logger.info("Scheduled scan triggered — scanning all active accounts")
    asyncio.run(_scan_all_accounts(config or {}))


async def _scan_all_accounts(config: dict) -> None:
    from app.core.database import AsyncSessionLocal
    from app.models.cloud_account import CloudAccount
    from app.models.scan import Scan, ScanStatus
    from sqlalchemy import select

    # Get all active accounts with valid credentials
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(CloudAccount).where(
                CloudAccount.is_active == True,
                CloudAccount.credentials_valid == True,
            )
        )
        accounts = result.scalars().all()

    logger.info(f"Scheduled scan: {len(accounts)} active account(s) found")

    for account in accounts:
        try:
            async with AsyncSessionLocal() as db:
                # Skip if scan already running for this account
                running = await db.execute(
                    select(Scan).where(
                        Scan.cloud_account_id == account.id,
                        Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
                    )
                )
                if running.scalar_one_or_none():
                    logger.info(f"  Skipping {account.name} — scan already running")
                    continue

                # Create a new scan record
                scan = Scan(
                    cloud_account_id=account.id,
                    scan_type=config.get("scan_type", "full"),
                    scan_config={
                        "source": "scheduled",
                        "include_ai_analysis": True,
                        "scheduled_at": __import__("datetime").datetime.utcnow().isoformat(),
                    },
                    status=ScanStatus.PENDING,
                )
                db.add(scan)
                await db.flush()
                scan_id      = str(scan.id)
                account_id   = str(account.id)
                account_name = account.name
                await db.commit()

            # Enqueue the scan task
            task = run_scan.delay(scan_id, account_id)

            # Save Celery task ID
            async with AsyncSessionLocal() as db:
                result = await db.execute(select(Scan).where(Scan.id == scan.id))
                s = result.scalar_one_or_none()
                if s:
                    s.celery_task_id = task.id
                    db.add(s)
                    await db.commit()

            logger.info(f"  ✅ Scheduled scan queued: {scan_id} for '{account_name}'")

        except Exception as exc:
            logger.error(f"  ❌ Failed to queue scan for {account.name}: {exc}")
