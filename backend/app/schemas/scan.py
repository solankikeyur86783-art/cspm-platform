from datetime import datetime
from typing import Optional, List, Dict, Any
import uuid

from pydantic import BaseModel, Field


class ScanConfig(BaseModel):
    services: Optional[List[str]] = None  # None means scan all
    regions: Optional[List[str]] = None
    include_ai_analysis: bool = True
    severity_threshold: str = "low"


class ScanCreate(BaseModel):
    cloud_account_id: uuid.UUID
    scan_type: str = Field(default="full", pattern="^(full|partial|quick)$")
    config: Optional[ScanConfig] = None


class ScanResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    status: str
    scan_type: str
    cloud_account_id: uuid.UUID
    celery_task_id: Optional[str] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    duration_seconds: Optional[int] = None
    total_findings: int
    critical_findings: int
    high_findings: int
    medium_findings: int
    low_findings: int
    info_findings: int
    risk_score: Optional[float] = None
    resources_scanned: int
    progress: int
    error_message: Optional[str] = None
    created_at: datetime


class ScanListResponse(BaseModel):
    items: List[ScanResponse]
    total: int
    page: int
    page_size: int


class ScanProgressEvent(BaseModel):
    scan_id: str
    status: str
    progress: int
    message: str
    findings_so_far: int = 0
    timestamp: datetime
