import asyncio
import uuid

from celery.utils.log import get_task_logger
from app.workers.celery_app import celery_app

logger = get_task_logger(__name__)


@celery_app.task(bind=True, name="app.workers.remediation_tasks.auto_remediate")
def auto_remediate(self, finding_id: str, approved_by: str):
    """Execute auto-remediation for a specific finding."""
    asyncio.run(_remediate(finding_id, approved_by))


async def _remediate(finding_id: str, approved_by: str) -> None:
    from app.core.database import AsyncSessionLocal
    from app.models.finding import Finding, FindingStatus
    from sqlalchemy import select

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Finding).where(Finding.id == uuid.UUID(finding_id)))
        finding: Finding = result.scalar_one_or_none()
        if not finding:
            logger.error(f"Finding {finding_id} not found for remediation")
            return

        try:
            success = await _dispatch_remediation(finding)
            if success:
                finding.status = FindingStatus.RESOLVED
                logger.info(f"Auto-remediated finding {finding_id} ({finding.rule_id})")
            else:
                logger.warning(f"Auto-remediation not available for {finding.rule_id}")
        except Exception as exc:
            logger.error(f"Auto-remediation failed for {finding_id}: {exc}")
        finally:
            db.add(finding)
            await db.commit()


async def _dispatch_remediation(finding) -> bool:
    """Route to appropriate remediation handler based on rule_id."""
    rule_id = finding.rule_id
    resource_id = finding.resource_id
    region = finding.region or "us-east-1"

    # S3 public access block
    if rule_id in ("CIS-S3-2.1.1", "S3-POLICY-001"):
        return await _remediate_s3_public_access(resource_id, region)

    # EBS encryption default
    if rule_id == "CIS-EC2-2.2.1":
        return await _remediate_ebs_encryption_default(region)

    # EC2 IMDSv2
    if rule_id == "EC2-IMDS-001":
        instance_id = resource_id.split("/")[-1] if "/" in resource_id else resource_id
        return await _remediate_imdsv2(instance_id, region)

    # RDS public access
    if rule_id == "CIS-RDS-2.3.2":
        db_id = finding.resource_name
        return await _remediate_rds_public_access(db_id, region)

    return False


async def _remediate_s3_public_access(bucket_name: str, region: str) -> bool:
    import boto3
    s3 = boto3.client("s3", region_name=region)
    bucket = bucket_name.replace("arn:aws:s3:::", "")
    s3.put_public_access_block(
        Bucket=bucket,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )
    logger.info(f"S3 public access blocked for bucket: {bucket}")
    return True


async def _remediate_ebs_encryption_default(region: str) -> bool:
    import boto3
    ec2 = boto3.client("ec2", region_name=region)
    ec2.enable_ebs_encryption_by_default()
    logger.info(f"EBS encryption by default enabled in {region}")
    return True


async def _remediate_imdsv2(instance_id: str, region: str) -> bool:
    import boto3
    ec2 = boto3.client("ec2", region_name=region)
    ec2.modify_instance_metadata_options(
        InstanceId=instance_id,
        HttpTokens="required",
        HttpEndpoint="enabled",
    )
    logger.info(f"IMDSv2 enforced on instance {instance_id}")
    return True


async def _remediate_rds_public_access(db_id: str, region: str) -> bool:
    import boto3
    rds = boto3.client("rds", region_name=region)
    rds.modify_db_instance(
        DBInstanceIdentifier=db_id,
        PubliclyAccessible=False,
        ApplyImmediately=True,
    )
    logger.info(f"RDS public access disabled for {db_id}")
    return True
