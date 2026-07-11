import asyncio
import uuid
import io
from datetime import datetime, timezone

from celery.utils.log import get_task_logger
from app.workers.celery_app import celery_app

logger = get_task_logger(__name__)


@celery_app.task(bind=True, name="app.workers.report_tasks.generate_pdf_report")
def generate_pdf_report(self, report_id: str, config: dict):
    asyncio.run(_generate_pdf(report_id, config))


async def _generate_pdf(report_id: str, config: dict) -> None:
    from app.core.database import AsyncSessionLocal
    from app.models.report import Report, ReportStatus
    from app.models.scan import Scan
    from app.models.finding import Finding
    from app.reporting.pdf_builder import PDFReportBuilder
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        report_result = await db.execute(select(Report).where(Report.id == uuid.UUID(report_id)))
        report: Report = report_result.scalar_one_or_none()
        if not report:
            logger.error(f"Report {report_id} not found")
            return

        scan_result = await db.execute(select(Scan).where(Scan.id == report.scan_id))
        scan: Scan = scan_result.scalar_one_or_none()

        findings_result = await db.execute(
            select(Finding).where(Finding.scan_id == report.scan_id)
            .order_by(Finding.severity)
        )
        findings = findings_result.scalars().all()

        try:
            builder = PDFReportBuilder()
            pdf_bytes = builder.build(
                scan=scan,
                findings=findings,
                title=report.title,
                config=config,
            )

            # Upload to S3
            s3_key = f"reports/{report.scan_id}/{report_id}.pdf"
            s3_url = await _upload_to_s3(pdf_bytes, s3_key)

            report.status = ReportStatus.READY
            report.s3_key = s3_key
            report.s3_url = s3_url
            report.file_size_bytes = len(pdf_bytes)
            report.summary = {
                "total_findings": scan.total_findings,
                "risk_score": scan.risk_score,
                "generated_at": datetime.now(timezone.utc).isoformat(),
            }

        except Exception as exc:
            logger.error(f"PDF generation failed for report {report_id}: {exc}")
            report.status = ReportStatus.FAILED
            report.error_message = str(exc)

        db.add(report)
        await db.commit()


async def _upload_to_s3(content: bytes, key: str) -> str:
    import boto3
    from app.core.config import settings

    s3 = boto3.client("s3", region_name=settings.S3_REGION)
    s3.put_object(
        Bucket=settings.S3_BUCKET_REPORTS,
        Key=key,
        Body=content,
        ContentType="application/pdf",
        ServerSideEncryption="AES256",
    )
    return f"https://{settings.S3_BUCKET_REPORTS}.s3.{settings.S3_REGION}.amazonaws.com/{key}"


@celery_app.task(name="app.workers.report_tasks.generate_daily_reports")
def generate_daily_reports():
    """Celery Beat daily task — generates PDF for every completed scan from last 24h."""
    import asyncio
    asyncio.run(_daily_reports())


async def _daily_reports() -> None:
    from app.core.database import AsyncSessionLocal
    from app.models.scan import Scan, ScanStatus
    from app.models.report import Report, ReportStatus
    from sqlalchemy import select
    from datetime import datetime, timezone, timedelta

    since = datetime.now(timezone.utc) - timedelta(hours=24)

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(Scan).where(
                Scan.status == ScanStatus.COMPLETED,
                Scan.completed_at >= since,
            )
        )
        scans = result.scalars().all()

    logger.info(f"Daily reports: generating for {len(scans)} scan(s)")

    for scan in scans:
        try:
            # Skip if report already exists for this scan
            async with AsyncSessionLocal() as db:
                existing = await db.execute(
                    select(Report).where(
                        Report.scan_id == scan.id,
                        Report.status == ReportStatus.READY,
                    )
                )
                if existing.scalar_one_or_none():
                    continue

                report = Report(
                    title=f"Daily Report — {scan.completed_at.strftime('%Y-%m-%d') if scan.completed_at else 'Unknown'}",
                    format="pdf",
                    scan_id=scan.id,
                    status=ReportStatus.GENERATING,
                    report_metadata={"source": "scheduled_daily"},
                )
                db.add(report)
                await db.flush()
                report_id = str(report.id)
                await db.commit()

            generate_pdf_report.delay(report_id, {"include_ai_summary": True, "include_remediation": True})
            logger.info(f"  Daily report queued: {report_id} for scan {scan.id}")
        except Exception as exc:
            logger.error(f"  Daily report failed for scan {scan.id}: {exc}")
