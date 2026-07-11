import uuid
from typing import List

from fastapi import APIRouter, status
from sqlalchemy import select, func, desc, asc, or_
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, AnalystUser, DB
from app.core.exceptions import http_not_found
from app.models.finding import Finding, Severity
from app.models.scan import Scan
from app.models.cloud_account import CloudAccount
from app.schemas.finding import (
    FindingFilter,
    FindingResponse,
    FindingListResponse,
    FindingSuppressRequest,
    FindingStatusUpdate,
)

router = APIRouter(prefix="/findings", tags=["Findings"])

SEVERITY_ORDER = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}


@router.post("/search", response_model=FindingListResponse)
async def search_findings(filters: FindingFilter, current_user: CurrentUser, db: DB):
    query = (
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(CloudAccount.owner_id == current_user.id)
    )

    if filters.scan_id:
        query = query.where(Finding.scan_id == filters.scan_id)
    if filters.severity:
        query = query.where(Finding.severity.in_(filters.severity))
    if filters.status:
        query = query.where(Finding.status == filters.status)
    if filters.cloud_provider:
        query = query.where(Finding.cloud_provider == filters.cloud_provider)
    if filters.resource_type:
        query = query.where(Finding.resource_type == filters.resource_type)
    if filters.rule_id:
        query = query.where(Finding.rule_id == filters.rule_id)
    if filters.region:
        query = query.where(Finding.region == filters.region)
    if filters.is_suppressed is not None:
        query = query.where(Finding.is_suppressed == filters.is_suppressed)
    if filters.search:
        term = f"%{filters.search}%"
        query = query.where(
            or_(
                Finding.rule_name.ilike(term),
                Finding.resource_id.ilike(term),
                Finding.resource_name.ilike(term),
            )
        )

    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()

    # Sort
    sort_col = getattr(Finding, filters.sort_by, Finding.severity)
    query = query.order_by(desc(sort_col) if filters.sort_desc else asc(sort_col))
    query = query.offset((filters.page - 1) * filters.page_size).limit(filters.page_size)

    items = (await db.execute(query)).scalars().all()

    # Severity breakdown for current filter (without pagination)
    breakdown_q = (
        select(Finding.severity, func.count(Finding.id))
        .join(Scan, Finding.scan_id == Scan.id)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(CloudAccount.owner_id == current_user.id)
        .group_by(Finding.severity)
    )
    breakdown_rows = (await db.execute(breakdown_q)).all()
    breakdown = {row[0]: row[1] for row in breakdown_rows}

    return FindingListResponse(
        items=items,
        total=total,
        page=filters.page,
        page_size=filters.page_size,
        severity_breakdown=breakdown,
    )


@router.get("/{finding_id}", response_model=FindingResponse)
async def get_finding(finding_id: uuid.UUID, current_user: CurrentUser, db: DB):
    return await _get_owned_finding(finding_id, current_user.id, db)


@router.put("/{finding_id}/suppress", response_model=FindingResponse)
async def suppress_finding(
    finding_id: uuid.UUID,
    payload: FindingSuppressRequest,
    current_user: AnalystUser,
    db: DB,
):
    finding = await _get_owned_finding(finding_id, current_user.id, db)
    finding.is_suppressed = True
    finding.status = "suppressed"
    finding.suppression_reason = payload.reason
    db.add(finding)
    await db.refresh(finding)
    return finding


@router.put("/{finding_id}/status", response_model=FindingResponse)
async def update_finding_status(
    finding_id: uuid.UUID,
    payload: FindingStatusUpdate,
    current_user: AnalystUser,
    db: DB,
):
    finding = await _get_owned_finding(finding_id, current_user.id, db)
    finding.status = payload.status
    if payload.status == "suppressed":
        finding.is_suppressed = True
        finding.suppression_reason = payload.reason
    elif payload.status in ("open", "resolved"):
        finding.is_suppressed = False
    db.add(finding)
    await db.refresh(finding)
    return finding


# ── Helper ───────────────────────────────────────────────────────────────────

async def _get_owned_finding(
    finding_id: uuid.UUID, user_id: uuid.UUID, db: AsyncSession
) -> Finding:
    result = await db.execute(
        select(Finding)
        .join(Scan, Finding.scan_id == Scan.id)
        .join(CloudAccount, Scan.cloud_account_id == CloudAccount.id)
        .where(Finding.id == finding_id, CloudAccount.owner_id == user_id)
    )
    finding = result.scalar_one_or_none()
    if not finding:
        raise http_not_found("Finding", str(finding_id))
    return finding
