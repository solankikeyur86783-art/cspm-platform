import uuid
from typing import List

from fastapi import APIRouter, status, BackgroundTasks
from fastapi.responses import StreamingResponse
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, AnalystUser, DB
from app.core.exceptions import http_not_found
from app.models.report import Report, ReportStatus
from app.models.scan import Scan
from app.models.cloud_account import CloudAccount
from app.schemas.report import ReportRequest, ReportResponse, ReportListResponse

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.post("", response_model=ReportResponse, status_code=status.HTTP_201_CREATED)
async def generate_report(
    payload: ReportRequest,
    current_user: AnalystUser,
    db: DB,
    background: BackgroundTasks,
):
    # Verify scan ownership
    result = await db.execute(
        select(Scan)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(
            Scan.id == payload.scan_id,
            CloudAccount.owner_id == current_user.id,
        )
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise http_not_found("Scan", str(payload.scan_id))

    title = payload.title or f"CSPM Report — {scan.created_at.strftime('%Y-%m-%d')}"

    report = Report(
        title=title,
        format=payload.format,
        scan_id=payload.scan_id,
        generated_by=current_user.id,
        status=ReportStatus.GENERATING,
        report_metadata=payload.model_dump(),
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)

    # Queue generation task
    background.add_task(_generate_report_bg, str(report.id), payload.model_dump())
    return report


@router.get("", response_model=ReportListResponse)
async def list_reports(current_user: CurrentUser, db: DB):
    rows = (
        await db.execute(
            select(Report)
            .join(Scan, Report.scan_id == Scan.id)
            .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
            .where(CloudAccount.owner_id == current_user.id)
            .order_by(desc(Report.created_at))
        )
    ).scalars().all()
    return ReportListResponse(items=rows, total=len(rows))


@router.get("/{report_id}", response_model=ReportResponse)
async def get_report(report_id: uuid.UUID, current_user: CurrentUser, db: DB):
    return await _get_owned_report(report_id, current_user.id, db)


@router.get("/{report_id}/download")
async def download_report(report_id: uuid.UUID, current_user: CurrentUser, db: DB):
    report = await _get_owned_report(report_id, current_user.id, db)

    if report.status != ReportStatus.READY:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Report is not ready (status: {report.status})",
        )

    # Stream from S3
    import boto3
    s3 = boto3.client("s3")
    from app.core.config import settings

    obj = s3.get_object(Bucket=settings.S3_BUCKET_REPORTS, Key=report.s3_key)
    content_types = {"pdf": "application/pdf", "html": "text/html", "csv": "text/csv"}
    media_type = content_types.get(report.format, "application/octet-stream")

    return StreamingResponse(
        content=obj["Body"].iter_chunks(),
        media_type=media_type,
        headers={"Content-Disposition": f'attachment; filename="{report.title}.{report.format}"'},
    )


@router.delete("/{report_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_report(report_id: uuid.UUID, current_user: AnalystUser, db: DB):
    report = await _get_owned_report(report_id, current_user.id, db)
    await db.delete(report)


# ── Helpers ───────────────────────────────────────────────────────────────────

async def _get_owned_report(
    report_id: uuid.UUID, user_id: uuid.UUID, db: AsyncSession
) -> Report:
    result = await db.execute(
        select(Report)
        .join(Scan, Report.scan_id == Scan.id)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(Report.id == report_id, CloudAccount.owner_id == user_id)
    )
    report = result.scalar_one_or_none()
    if not report:
        raise http_not_found("Report", str(report_id))
    return report


async def _generate_report_bg(report_id: str, config: dict) -> None:
    from app.core.database import AsyncSessionLocal
    from app.workers.report_tasks import generate_pdf_report

    try:
        generate_pdf_report.delay(report_id, config)
    except Exception as exc:
        from app.core.logging import logger
        logger.error(f"Failed to queue report generation: {exc}")
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(Report).where(Report.id == uuid.UUID(report_id))
            )
            report = result.scalar_one_or_none()
            if report:
                report.status = ReportStatus.FAILED
                report.error_message = str(exc)
                db.add(report)
                await db.commit()
