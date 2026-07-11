from typing import Annotated
import uuid

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.core.database import get_db
from app.core.security import decode_token, verify_api_key
from app.core.exceptions import http_unauthorized, http_forbidden
from app.models.user import User, UserRole

bearer_scheme = HTTPBearer(auto_error=False)


async def get_current_user(
    db: Annotated[AsyncSession, Depends(get_db)],
    credentials: Annotated[HTTPAuthorizationCredentials | None, Depends(bearer_scheme)] = None,
    x_api_key: Annotated[str | None, Header()] = None,
) -> User:
    user: User | None = None

    # API key auth
    if x_api_key:
        result = await db.execute(
            select(User).where(User.api_key_prefix == x_api_key[:12])
        )
        candidate = result.scalar_one_or_none()
        if candidate and verify_api_key(x_api_key, candidate.api_key_hash):
            user = candidate

    # JWT auth
    elif credentials:
        try:
            payload = decode_token(credentials.credentials)
            if payload.get("type") != "access":
                raise http_unauthorized("Invalid token type")
            user_id = payload.get("sub")
            result = await db.execute(select(User).where(User.id == uuid.UUID(user_id)))
            user = result.scalar_one_or_none()
        except Exception:
            raise http_unauthorized("Invalid or expired token")

    if not user:
        raise http_unauthorized()

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    return user


def require_role(*roles: UserRole):
    async def role_checker(
        current_user: Annotated[User, Depends(get_current_user)],
    ) -> User:
        if current_user.role not in [r.value for r in roles]:
            raise http_forbidden(f"Requires one of roles: {[r.value for r in roles]}")
        return current_user
    return role_checker


# Convenience aliases
CurrentUser = Annotated[User, Depends(get_current_user)]
AdminUser = Annotated[User, Depends(require_role(UserRole.ADMIN))]
AnalystUser = Annotated[User, Depends(require_role(UserRole.ADMIN, UserRole.ANALYST))]
DB = Annotated[AsyncSession, Depends(get_db)]
