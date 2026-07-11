import pytest
import asyncio
import boto3
from moto import mock_aws


@mock_aws
def test_rds_scanner_detects_public_instance():
    """Publicly accessible RDS instance should trigger CIS-RDS-2.3.2."""
    from app.scanners.aws.rds import AWSRDSScanner

    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="public-db",
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="Password123!",
        PubliclyAccessible=True,
        AllocatedStorage=20,
    )

    scanner = AWSRDSScanner({"aws_regions": ["us-east-1"]})
    result = asyncio.run(scanner.scan())

    rule_ids = [f.rule_id for f in result.findings]
    assert "CIS-RDS-2.3.2" in rule_ids


@mock_aws
def test_rds_scanner_detects_no_deletion_protection():
    """RDS without deletion protection should be flagged."""
    from app.scanners.aws.rds import AWSRDSScanner

    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="no-protect-db",
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        MasterUsername="admin",
        MasterUserPassword="Password123!",
        PubliclyAccessible=False,
        DeletionProtection=False,
        AllocatedStorage=20,
    )

    scanner = AWSRDSScanner({"aws_regions": ["us-east-1"]})
    result = asyncio.run(scanner.scan())

    rule_ids = [f.rule_id for f in result.findings]
    assert "RDS-DEL-001" in rule_ids


@mock_aws
def test_rds_scanner_detects_short_backup_retention():
    """RDS with backup retention < 7 days should be flagged."""
    from app.scanners.aws.rds import AWSRDSScanner

    rds = boto3.client("rds", region_name="us-east-1")
    rds.create_db_instance(
        DBInstanceIdentifier="short-backup-db",
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="Password123!",
        BackupRetentionPeriod=1,
        AllocatedStorage=20,
    )

    scanner = AWSRDSScanner({"aws_regions": ["us-east-1"]})
    result = asyncio.run(scanner.scan())

    rule_ids = [f.rule_id for f in result.findings]
    assert "RDS-BACKUP-001" in rule_ids


@mock_aws
def test_rds_scanner_empty_account():
    """No RDS instances = no findings."""
    from app.scanners.aws.rds import AWSRDSScanner

    scanner = AWSRDSScanner({"aws_regions": ["us-east-1"]})
    result = asyncio.run(scanner.scan())

    assert result.resources_scanned == 0
    assert len(result.findings) == 0
