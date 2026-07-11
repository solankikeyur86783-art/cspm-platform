import uuid
from enum import Enum
from typing import Optional

from sqlalchemy import String, Text, ForeignKey, JSON, Float, Boolean
from sqlalchemy.orm import Mapped, mapped_column, relationship
from sqlalchemy.dialects.postgresql import UUID

from app.core.database import Base
from app.models.base import UUIDMixin, TimestampMixin


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingStatus(str, Enum):
    OPEN = "open"
    SUPPRESSED = "suppressed"
    RESOLVED = "resolved"
    IN_PROGRESS = "in_progress"


class Finding(Base, UUIDMixin, TimestampMixin):
    __tablename__ = "findings"

    # Rule info
    rule_id: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    rule_name: Mapped[str] = mapped_column(String(500), nullable=False)
    rule_description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Severity & scoring
    severity: Mapped[str] = mapped_column(String(20), nullable=False, index=True)
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(200), nullable=True)

    # Resource info
    resource_id: Mapped[str] = mapped_column(String(500), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_name: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    resource_arn: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    region: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cloud_provider: Mapped[str] = mapped_column(String(20), nullable=False, index=True)

    # Finding details
    status: Mapped[str] = mapped_column(
        String(20), default=FindingStatus.OPEN, nullable=False, index=True
    )
    is_suppressed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    suppression_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Evidence & context
    evidence: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    affected_asset: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)

    # Compliance mappings
    cis_benchmark_refs: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    mitre_attack_techniques: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)
    compliance_frameworks: Mapped[Optional[list]] = mapped_column(JSON, nullable=True)

    # Remediation
    remediation_steps: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    remediation_code: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_explanation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ai_remediation: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # Foreign keys
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
        index=True,
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")

    def __repr__(self) -> str:
        return f"<Finding rule={self.rule_id} severity={self.severity} resource={self.resource_id}>"
