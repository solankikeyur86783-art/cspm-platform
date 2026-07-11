import uuid
from enum import Enum
from typing import Optional, List
from datetime import datetime

from sqlalchemy import String, Boolean, Text, ForeignKey, JSON, Integer, Float, DateTime
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class ScanStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanType(str, Enum):
    FULL = "full"
    PARTIAL = "partial"
    QUICK = "quick"


class Scan(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "scans"

    # Status
    status: Mapped[str] = mapped_column(
        String(50), default=ScanStatus.PENDING, nullable=False, index=True
    )
    scan_type: Mapped[str] = mapped_column(String(50), default=ScanType.FULL, nullable=False)

    # Celery task tracking
    celery_task_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # Timing
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    duration_seconds: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)

    # Results summary
    total_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    critical_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    high_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    medium_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    low_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    info_findings: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Risk score (0-100, higher = more risk)
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)

    # Services scanned config
    scan_config: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    services_scanned: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    resources_scanned: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Error info
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Progress (0-100)
    progress: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # Foreign keys
    cloud_account_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("cloud_accounts.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )
    initiated_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    # Relationships
    cloud_account: Mapped["CloudAccount"] = relationship("CloudAccount", back_populates="scans")
    initiated_by_user: Mapped[Optional["User"]] = relationship("User", back_populates="scans")
    findings: Mapped[List["Finding"]] = relationship(
        "Finding", back_populates="scan", cascade="all, delete-orphan"
    )
    reports: Mapped[List["Report"]] = relationship(
        "Report", back_populates="scan", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} status={self.status} findings={self.total_findings}>"
