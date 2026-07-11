from datetime import datetime
from typing import Optional, List
import uuid

from pydantic import BaseModel, Field


class CloudAccountCreate(BaseModel):
    name: str = Field(..., min_length=2, max_length=255)
    provider: str = Field(..., pattern="^(aws|gcp|azure)$")

    # AWS
    aws_account_id: Optional[str] = None
    aws_role_arn: Optional[str] = None
    aws_regions: Optional[List[str]] = None

    # GCP
    gcp_project_id: Optional[str] = None
    gcp_service_account_email: Optional[str] = None

    # Azure
    azure_subscription_id: Optional[str] = None
    azure_tenant_id: Optional[str] = None


class CloudAccountUpdate(BaseModel):
    name: Optional[str] = None
    is_active: Optional[bool] = None
    aws_regions: Optional[List[str]] = None


class CloudAccountResponse(BaseModel):
    model_config = {"from_attributes": True}

    id: uuid.UUID
    name: str
    provider: str
    is_active: bool
    aws_account_id: Optional[str] = None
    aws_role_arn: Optional[str] = None
    aws_regions: Optional[List[str]] = None
    gcp_project_id: Optional[str] = None
    azure_subscription_id: Optional[str] = None
    credentials_valid: bool
    last_validation_error: Optional[str] = None
    scan_count: int
    last_scanned_at: Optional[str] = None
    created_at: datetime


class CloudAccountValidation(BaseModel):
    is_valid: bool
    provider: str
    error: Optional[str] = None
    permissions_checked: Optional[List[str]] = None
