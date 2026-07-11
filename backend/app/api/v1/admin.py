"""
Admin API — user management, system stats. Admin-only.
"""
import uuid
from typing import List

from fastapi import APIRouter, HTTPException, status
from pydantic import BaseModel
from sqlalchemy import select, func

from app.api.deps import AdminUser, DB
from app.core.exceptions import http_not_found
from app.models.user import User, UserRole
from app.models.scan import Scan, ScanStatus
from app.models.cloud_account import CloudAccount
from app.schemas.auth import UserResponse

router = APIRouter(prefix="/admin", tags=["Admin"])


class UserUpdate(BaseModel):
    role: str | None = None
    is_active: bool | None = None


class SystemStats(BaseModel):
    total_users: int
    total_cloud_accounts: int
    total_scans: int
    completed_scans: int
    failed_scans: int
    running_scans: int


@router.get("/users", response_model=List[UserResponse])
async def list_all_users(current_user: AdminUser, db: DB):
    result = await db.execute(select(User).order_by(User.created_at.desc()))
    return result.scalars().all()


@router.get("/users/{user_id}", response_model=UserResponse)
async def get_user(user_id: uuid.UUID, current_user: AdminUser, db: DB):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise http_not_found("User", str(user_id))
    return user


@router.put("/users/{user_id}", response_model=UserResponse)
async def update_user(user_id: uuid.UUID, payload: UserUpdate, current_user: AdminUser, db: DB):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise http_not_found("User", str(user_id))

    if payload.role is not None:
        if payload.role not in [r.value for r in UserRole]:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"Invalid role. Must be one of: {[r.value for r in UserRole]}",
            )
        user.role = payload.role

    if payload.is_active is not None:
        user.is_active = payload.is_active

    db.add(user)
    await db.refresh(user)
    return user


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_user(user_id: uuid.UUID, current_user: AdminUser, db: DB):
    if user_id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account",
        )
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise http_not_found("User", str(user_id))
    await db.delete(user)


@router.get("/stats", response_model=SystemStats)
async def get_system_stats(current_user: AdminUser, db: DB):
    total_users = (await db.execute(select(func.count(User.id)))).scalar_one()
    total_accounts = (await db.execute(select(func.count(CloudAccount.id)))).scalar_one()
    total_scans = (await db.execute(select(func.count(Scan.id)))).scalar_one()
    completed = (await db.execute(
        select(func.count(Scan.id)).where(Scan.status == ScanStatus.COMPLETED)
    )).scalar_one()
    failed = (await db.execute(
        select(func.count(Scan.id)).where(Scan.status == ScanStatus.FAILED)
    )).scalar_one()
    running = (await db.execute(
        select(func.count(Scan.id)).where(Scan.status == ScanStatus.RUNNING)
    )).scalar_one()

    return SystemStats(
        total_users=total_users,
        total_cloud_accounts=total_accounts,
        total_scans=total_scans,
        completed_scans=completed,
        failed_scans=failed,
        running_scans=running,
    )


@router.post("/users/{user_id}/verify", response_model=UserResponse)
async def verify_user(user_id: uuid.UUID, current_user: AdminUser, db: DB):
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if not user:
        raise http_not_found("User", str(user_id))
    user.is_verified = True
    db.add(user)
    await db.refresh(user)
    return user
