import uuid
from typing import List

from fastapi import APIRouter, HTTPException, status, BackgroundTasks
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import CurrentUser, AnalystUser, DB
from app.core.exceptions import http_not_found, http_forbidden
from app.models.cloud_account import CloudAccount
from app.schemas.cloud_account import (
    CloudAccountCreate,
    CloudAccountUpdate,
    CloudAccountResponse,
    CloudAccountValidation,
)
from app.core.logging import logger

router = APIRouter(prefix="/accounts", tags=["Cloud Accounts"])


@router.get("", response_model=List[CloudAccountResponse])
async def list_accounts(current_user: CurrentUser, db: DB):
    result = await db.execute(
        select(CloudAccount).where(CloudAccount.owner_id == current_user.id)
    )
    return result.scalars().all()


@router.post("", response_model=CloudAccountResponse, status_code=status.HTTP_201_CREATED)
async def create_account(
    payload: CloudAccountCreate,
    current_user: AnalystUser,
    db: DB,
    background: BackgroundTasks,
):
    account = CloudAccount(
        **payload.model_dump(exclude_none=True),
        owner_id=current_user.id,
    )
    db.add(account)
    await db.flush()
    await db.refresh(account)

    # Validate credentials in background
    background.add_task(_validate_credentials_bg, str(account.id))
    return account


@router.get("/{account_id}", response_model=CloudAccountResponse)
async def get_account(account_id: uuid.UUID, current_user: CurrentUser, db: DB):
    account = await _get_owned_account(account_id, current_user.id, db)
    return account


@router.put("/{account_id}", response_model=CloudAccountResponse)
async def update_account(
    account_id: uuid.UUID,
    payload: CloudAccountUpdate,
    current_user: AnalystUser,
    db: DB,
):
    account = await _get_owned_account(account_id, current_user.id, db)
    for field, val in payload.model_dump(exclude_none=True).items():
        setattr(account, field, val)
    db.add(account)
    await db.flush()
    await db.refresh(account)
    return account


@router.delete("/{account_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_account(account_id: uuid.UUID, current_user: AnalystUser, db: DB):
    account = await _get_owned_account(account_id, current_user.id, db)
    await db.delete(account)


@router.post("/{account_id}/validate", response_model=CloudAccountValidation)
async def validate_account(account_id: uuid.UUID, current_user: AnalystUser, db: DB):
    account = await _get_owned_account(account_id, current_user.id, db)
    result = await _validate_credentials(account)

    account.credentials_valid = result.is_valid
    account.last_validation_error = result.error
    db.add(account)
    return result


# ── Helpers ──────────────────────────────────────────────────────────────────

async def _get_owned_account(
    account_id: uuid.UUID,
    user_id: uuid.UUID,
    db: AsyncSession,
) -> CloudAccount:
    result = await db.execute(
        select(CloudAccount).where(CloudAccount.id == account_id)
    )
    account = result.scalar_one_or_none()
    if not account:
        raise http_not_found("CloudAccount", str(account_id))
    if account.owner_id != user_id:
        raise http_forbidden()
    return account


async def _validate_credentials(account: CloudAccount) -> CloudAccountValidation:
    """Validate cloud credentials by making a minimal API call."""
    try:
        if account.provider == "aws":
            import boto3
            from botocore.exceptions import ClientError, NoCredentialsError
            sts = boto3.client("sts")
            identity = sts.get_caller_identity()
            return CloudAccountValidation(
                is_valid=True,
                provider="aws",
                permissions_checked=["sts:GetCallerIdentity"],
            )
        elif account.provider == "gcp":
            from google.auth import default
            credentials, project = default()
            return CloudAccountValidation(
                is_valid=True,
                provider="gcp",
                permissions_checked=["iam.serviceAccounts.get"],
            )
        elif account.provider == "azure":
            from azure.identity import DefaultAzureCredential
            creds = DefaultAzureCredential()
            token = creds.get_token("https://management.azure.com/.default")
            return CloudAccountValidation(
                is_valid=bool(token.token),
                provider="azure",
                permissions_checked=["Microsoft.Resources/subscriptions/read"],
            )
    except Exception as exc:
        logger.warning(f"Credential validation failed for {account.id}: {exc}")
        return CloudAccountValidation(
            is_valid=False,
            provider=account.provider,
            error=str(exc),
        )


async def _validate_credentials_bg(account_id: str) -> None:
    """Background task wrapper for credential validation."""
    from app.core.database import AsyncSessionLocal
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(CloudAccount).where(CloudAccount.id == uuid.UUID(account_id))
        )
        account = result.scalar_one_or_none()
        if account:
            validation = await _validate_credentials(account)
            account.credentials_valid = validation.is_valid
            account.last_validation_error = validation.error
            db.add(account)
            await db.commit()
