import uuid
from enum import Enum
from typing import List, Optional

from sqlalchemy import String, Boolean, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID, ARRAY

from app.core.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class User(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "users"

    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=False)
    hashed_password: Mapped[str] = mapped_column(Text, nullable=False)
    role: Mapped[str] = mapped_column(String(50), default=UserRole.ANALYST, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # API keys stored as hashes
    api_key_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    api_key_prefix: Mapped[Optional[str]] = mapped_column(String(16), nullable=True)

    # Relationships
    cloud_accounts: Mapped[List["CloudAccount"]] = relationship(
        "CloudAccount", back_populates="owner", cascade="all, delete-orphan"
    )
    scans: Mapped[List["Scan"]] = relationship(
        "Scan", back_populates="initiated_by_user"
    )

    def __repr__(self) -> str:
        return f"<User email={self.email} role={self.role}>"
