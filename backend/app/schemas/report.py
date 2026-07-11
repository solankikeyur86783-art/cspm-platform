from datetime import datetime
from typing import Optional, Dict, Any
import uuid

from pydantic import BaseModel, Field


class ReportRequest(BaseModel):
    scan_id: uuid.UUID
    title: Optional[str] = None
    format: str = Field(default="pdf", pattern="^(pdf|html|json|csv)$")
    include_ai_summary: bool = True
    include_remediation: bool = True
    include_compliance_mapping: bool = True
    severity_filter: Optional[str] = None  # min severity to include


class ReportResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    title: str
    status: str
    format: str
    s3_url: Optional[str] = None
    file_size_bytes: Optional[int] = None
    summary: Optional[Dict[str, Any]] = None
    error_message: Optional[str] = None
    scan_id: uuid.UUID
    created_at: datetime


class ReportListResponse(BaseModel):
    items: list[ReportResponse]
    total: int
