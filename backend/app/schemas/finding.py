from datetime import datetime
from typing import Optional, List, Any, Dict
import uuid

from pydantic import BaseModel, Field


class FindingFilter(BaseModel):
    scan_id: Optional[uuid.UUID] = None
    severity: Optional[List[str]] = None
    status: Optional[str] = None
    cloud_provider: Optional[str] = None
    resource_type: Optional[str] = None
    rule_id: Optional[str] = None
    region: Optional[str] = None
    is_suppressed: Optional[bool] = False
    search: Optional[str] = None
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=50, ge=1, le=200)
    sort_by: str = "severity"
    sort_desc: bool = True


class FindingResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    rule_id: str
    rule_name: str
    rule_description: Optional[str] = None
    severity: str
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    resource_id: str
    resource_type: str
    resource_name: Optional[str] = None
    resource_arn: Optional[str] = None
    region: Optional[str] = None
    cloud_provider: str
    status: str
    is_suppressed: bool
    evidence: Optional[Dict[str, Any]] = None
    cis_benchmark_refs: Optional[List[str]] = None
    mitre_attack_techniques: Optional[List[str]] = None
    compliance_frameworks: Optional[List[str]] = None
    remediation_steps: Optional[str] = None
    remediation_code: Optional[str] = None
    ai_explanation: Optional[str] = None
    ai_remediation: Optional[str] = None
    scan_id: uuid.UUID
    created_at: datetime


class FindingListResponse(BaseModel):
    items: List[FindingResponse]
    total: int
    page: int
    page_size: int
    severity_breakdown: Dict[str, int] = {}


class FindingSuppressRequest(BaseModel):
    reason: str = Field(..., min_length=10, max_length=1000)


class FindingStatusUpdate(BaseModel):
    status: str = Field(..., pattern="^(open|suppressed|resolved|in_progress)$")
    reason: Optional[str] = None
