import pytest
import asyncio
import json
import boto3
from moto import mock_aws


@mock_aws
def test_s3_scanner_detects_unencrypted_bucket():
    """Bucket without SSE should trigger CIS-S3-2.1.2."""
    from app.scanners.aws.s3 import AWSS3Scanner

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-unencrypted-bucket")

    scanner = AWSS3Scanner({"region": "us-east-1"})
    result = asyncio.run(scanner.scan())

    rule_ids = [f.rule_id for f in result.findings]
    assert "CIS-S3-2.1.2" in rule_ids


@mock_aws
def test_s3_scanner_detects_no_versioning():
    """Bucket without versioning should trigger CIS-S3-2.1.3."""
    from app.scanners.aws.s3 import AWSS3Scanner

    s3 = boto3.client("s3", region_name="us-east-1")
    s3.create_bucket(Bucket="test-no-versioning")

    scanner = AWSS3Scanner({"region": "us-east-1"})
    result = asyncio.run(scanner.scan())

    rule_ids = [f.rule_id for f in result.findings]
    assert "CIS-S3-2.1.3" in rule_ids


@mock_aws
def test_s3_scanner_clean_bucket_no_critical():
    """Properly configured bucket should have no critical findings."""
    from app.scanners.aws.s3 import AWSS3Scanner

    s3 = boto3.client("s3", region_name="us-east-1")
    bucket_name = "test-secure-bucket"
    s3.create_bucket(Bucket=bucket_name)

    # Enable encryption
    s3.put_bucket_encryption(
        Bucket=bucket_name,
        ServerSideEncryptionConfiguration={
            "Rules": [{"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}}]
        },
    )
    # Enable versioning
    s3.put_bucket_versioning(
        Bucket=bucket_name,
        VersioningConfiguration={"Status": "Enabled"},
    )
    # Block public access
    s3.put_public_access_block(
        Bucket=bucket_name,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": True,
            "IgnorePublicAcls": True,
            "BlockPublicPolicy": True,
            "RestrictPublicBuckets": True,
        },
    )

    scanner = AWSS3Scanner({"region": "us-east-1"})
    result = asyncio.run(scanner.scan())

    bucket_findings = [f for f in result.findings if bucket_name in f.resource_id]
    critical = [f for f in bucket_findings if f.severity == "critical"]
    assert len(critical) == 0


@mock_aws
def test_s3_scanner_empty_account_no_findings():
    """Account with no buckets should produce no findings."""
    from app.scanners.aws.s3 import AWSS3Scanner

    scanner = AWSS3Scanner({"region": "us-east-1"})
    result = asyncio.run(scanner.scan())
    assert len(result.findings) == 0
    assert result.resources_scanned == 0
