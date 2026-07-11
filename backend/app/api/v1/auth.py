from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, DB
from app.core.config import settings
from app.core.security import (
    hash_password,
    verify_password,
    create_access_token,
    create_refresh_token,
    decode_token,
    generate_api_key,
)
from app.core.exceptions import http_unauthorized, http_conflict
from app.models.user import User
from app.schemas.auth import (
    UserRegister,
    UserLogin,
    TokenResponse,
    RefreshRequest,
    UserResponse,
    APIKeyResponse,
    PasswordChange,
)

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/register", response_model=UserResponse, status_code=status.HTTP_201_CREATED)
async def register(payload: UserRegister, db: DB):
    result = await db.execute(select(User).where(User.email == payload.email))
    if result.scalar_one_or_none():
        raise http_conflict(f"Email '{payload.email}' is already registered")

    user = User(
        email=payload.email,
        full_name=payload.full_name,
        hashed_password=hash_password(payload.password),
    )
    db.add(user)
    await db.flush()
    await db.refresh(user)
    return user


@router.post("/login", response_model=TokenResponse)
async def login(payload: UserLogin, db: DB):
    result = await db.execute(select(User).where(User.email == payload.email))
    user: User | None = result.scalar_one_or_none()

    if not user or not verify_password(payload.password, user.hashed_password):
        raise http_unauthorized("Invalid email or password")

    if not user.is_active:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Account deactivated")

    return TokenResponse(
        access_token=create_access_token(str(user.id), {"role": user.role}),
        refresh_token=create_refresh_token(str(user.id)),
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token(payload: RefreshRequest, db: DB):
    try:
        data = decode_token(payload.refresh_token)
        if data.get("type") != "refresh":
            raise ValueError("Not a refresh token")
    except Exception:
        raise http_unauthorized("Invalid or expired refresh token")

    import uuid
    result = await db.execute(select(User).where(User.id == uuid.UUID(data["sub"])))
    user: User | None = result.scalar_one_or_none()

    if not user or not user.is_active:
        raise http_unauthorized()

    return TokenResponse(
        access_token=create_access_token(str(user.id), {"role": user.role}),
        refresh_token=create_refresh_token(str(user.id)),
        expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.get("/me", response_model=UserResponse)
async def get_me(current_user: CurrentUser):
    return current_user


@router.put("/me/password", status_code=status.HTTP_204_NO_CONTENT)
async def change_password(payload: PasswordChange, current_user: CurrentUser, db: DB):
    if not verify_password(payload.current_password, current_user.hashed_password):
        raise http_unauthorized("Current password is incorrect")

    current_user.hashed_password = hash_password(payload.new_password)
    db.add(current_user)


@router.post("/api-key", response_model=APIKeyResponse)
async def create_api_key(current_user: CurrentUser, db: DB):
    raw_key, hashed = generate_api_key()
    current_user.api_key_hash = hashed
    current_user.api_key_prefix = raw_key[:12]
    db.add(current_user)
    return APIKeyResponse(api_key=raw_key, prefix=raw_key[:12])


@router.delete("/api-key", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_api_key(current_user: CurrentUser, db: DB):
    current_user.api_key_hash = None
    current_user.api_key_prefix = None
    db.add(current_user)
