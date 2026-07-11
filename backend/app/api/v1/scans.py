import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, AnalystUser, DB
from app.core.exceptions import http_not_found, http_forbidden
from app.core.logging import logger
from app.core.redis_client import cache
from app.models.scan import Scan, ScanStatus
from app.models.cloud_account import CloudAccount
from app.schemas.scan import ScanCreate, ScanResponse, ScanListResponse

router = APIRouter(prefix="/scans", tags=["Scans"])


@router.post("", response_model=ScanResponse, status_code=status.HTTP_201_CREATED)
async def start_scan(payload: ScanCreate, current_user: AnalystUser, db: DB):
    # Verify account ownership
    result = await db.execute(
        select(CloudAccount).where(
            CloudAccount.id == payload.cloud_account_id,
            CloudAccount.owner_id == current_user.id,
        )
    )
    account = result.scalar_one_or_none()
    if not account:
        raise http_not_found("CloudAccount", str(payload.cloud_account_id))

    if not account.credentials_valid:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cloud account credentials are not valid. Please validate first.",
        )

    # Check for already-running scan
    running = await db.execute(
        select(Scan).where(
            Scan.cloud_account_id == payload.cloud_account_id,
            Scan.status.in_([ScanStatus.PENDING, ScanStatus.RUNNING]),
        )
    )
    if running.scalar_one_or_none():
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A scan is already running for this account.",
        )

    scan = Scan(
        cloud_account_id=payload.cloud_account_id,
        scan_type=payload.scan_type,
        initiated_by=current_user.id,
        scan_config=payload.config.model_dump() if payload.config else {},
        status=ScanStatus.PENDING,
    )
    db.add(scan)
    await db.flush()
    await db.refresh(scan)

    # Enqueue Celery task
    try:
        from app.workers.scan_tasks import run_scan
        task = run_scan.delay(str(scan.id), str(account.id))
        scan.celery_task_id = task.id
        db.add(scan)
    except Exception as exc:
        logger.error(f"Failed to enqueue scan task: {exc}")
        scan.status = ScanStatus.FAILED
        scan.error_message = "Failed to queue scan task"
        db.add(scan)

    # Cache initial status
    await cache.set_scan_status(str(scan.id), {"status": "pending", "progress": 0})
    return scan


@router.get("", response_model=ScanListResponse)
async def list_scans(
    current_user: CurrentUser,
    db: DB,
    account_id: uuid.UUID | None = None,
    status: str | None = None,
    page: int = 1,
    page_size: int = 20,
):
    # Join to CloudAccount to filter by owner
    query = (
        select(Scan)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(CloudAccount.owner_id == current_user.id)
        .order_by(desc(Scan.created_at))
    )
    if account_id:
        query = query.where(Scan.cloud_account_id == account_id)
    if status:
        query = query.where(Scan.status == status)

    count_q = select(func.count()).select_from(query.subquery())
    total = (await db.execute(count_q)).scalar_one()

    scans = (
        await db.execute(query.offset((page - 1) * page_size).limit(page_size))
    ).scalars().all()

    return ScanListResponse(items=scans, total=total, page=page, page_size=page_size)


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: uuid.UUID, current_user: CurrentUser, db: DB):
    scan = await _get_owned_scan(scan_id, current_user.id, db)
    return scan


@router.get("/{scan_id}/status")
async def get_scan_status(scan_id: uuid.UUID, current_user: CurrentUser, db: DB):
    scan = await _get_owned_scan(scan_id, current_user.id, db)
    cached = await cache.get_scan_status(str(scan_id))
    return {
        "scan_id": str(scan_id),
        "status": scan.status,
        "progress": scan.progress,
        "total_findings": scan.total_findings,
        "risk_score": scan.risk_score,
        "live_data": cached,
    }


@router.post("/{scan_id}/cancel", response_model=ScanResponse)
async def cancel_scan(scan_id: uuid.UUID, current_user: AnalystUser, db: DB):
    scan = await _get_owned_scan(scan_id, current_user.id, db)

    if scan.status not in [ScanStatus.PENDING, ScanStatus.RUNNING]:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Cannot cancel scan with status '{scan.status}'",
        )

    if scan.celery_task_id:
        try:
            from app.workers.celery_app import celery_app
            celery_app.control.revoke(scan.celery_task_id, terminate=True)
        except Exception as exc:
            logger.warning(f"Could not revoke Celery task: {exc}")

    scan.status = ScanStatus.CANCELLED
    scan.completed_at = datetime.now(timezone.utc)
    db.add(scan)
    return scan


# ── Helper ───────────────────────────────────────────────────────────────────

async def _get_owned_scan(scan_id: uuid.UUID, user_id: uuid.UUID, db: AsyncSession) -> Scan:
    result = await db.execute(
        select(Scan)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(Scan.id == scan_id, CloudAccount.owner_id == user_id)
    )
    scan = result.scalar_one_or_none()
    if not scan:
        raise http_not_found("Scan", str(scan_id))
    return scan
