import uuid
from enum import Enum
from typing import Optional, List

from sqlalchemy import String, Boolean, Text, ForeignKey, JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class CloudProvider(str, Enum):
    AWS = "aws"
    GCP = "gcp"
    AZURE = "azure"


class CloudAccount(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "cloud_accounts"

    name: Mapped[str] = mapped_column(String(255), nullable=False)
    provider: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # AWS specific
    aws_account_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    aws_role_arn: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    aws_regions: Mapped[Optional[list]] = mapped_column(JSON, nullable=True, default=list)

    # GCP specific
    gcp_project_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    gcp_service_account_email: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Azure specific
    azure_subscription_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    azure_tenant_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)

    # Metadata
    last_scanned_at: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    scan_count: Mapped[int] = mapped_column(default=0, nullable=False)
    credentials_valid: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    last_validation_error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Owner
    owner_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("users.id", ondelete="CASCADE"), nullable=False
    )
    owner: Mapped["User"] = relationship("User", back_populates="cloud_accounts")

    # Scans
    scans: Mapped[List["Scan"]] = relationship(
        "Scan", back_populates="cloud_account", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<CloudAccount name={self.name} provider={self.provider}>"
