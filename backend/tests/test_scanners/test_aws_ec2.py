import pytest
import asyncio
import boto3
from moto import mock_aws


@mock_aws
def test_ec2_scanner_detects_open_ssh_security_group():
    """Security group allowing SSH from 0.0.0.0/0 should be flagged."""
    from app.scanners.aws.ec2 import AWSEC2Scanner

    ec2 = boto3.client("ec2", region_name="us-east-1")
    # Create a security group with open SSH
    sg = ec2.create_security_group(
        GroupName="open-ssh-sg",
        Description="Dangerously open SG",
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
        }],
    )

    scanner = AWSEC2Scanner({"aws_regions": ["us-east-1"]})
    result = asyncio.run(scanner.scan())

    rule_ids = [f.rule_id for f in result.findings]
    assert "CIS-EC2-5.2" in rule_ids or "CIS-EC2-5.3" in rule_ids, \
        f"Expected SSH/RDP finding, got: {rule_ids}"


@mock_aws
def test_ec2_scanner_detects_ebs_encryption_disabled():
    """EBS encryption by default disabled should trigger CIS-EC2-2.2.1."""
    from app.scanners.aws.ec2 import AWSEC2Scanner

    # moto has EBS encryption disabled by default
    scanner = AWSEC2Scanner({"aws_regions": ["us-east-1"]})
    result = asyncio.run(scanner.scan())

    rule_ids = [f.rule_id for f in result.findings]
    assert "CIS-EC2-2.2.1" in rule_ids


@mock_aws
def test_ec2_scanner_clean_sg_no_finding():
    """Properly restricted security group should not be flagged."""
    from app.scanners.aws.ec2 import AWSEC2Scanner

    ec2 = boto3.client("ec2", region_name="us-east-1")
    sg = ec2.create_security_group(
        GroupName="restricted-sg",
        Description="Properly restricted",
    )
    ec2.authorize_security_group_ingress(
        GroupId=sg["GroupId"],
        IpPermissions=[{
            "IpProtocol": "tcp",
            "FromPort": 22,
            "ToPort": 22,
            "IpRanges": [{"CidrIp": "10.0.0.0/8"}],  # Private only
        }],
    )

    scanner = AWSEC2Scanner({"aws_regions": ["us-east-1"]})
    result = asyncio.run(scanner.scan())

    ssh_findings = [f for f in result.findings if "5.2" in f.rule_id or "5.3" in f.rule_id]
    # No open SSH findings expected
    open_ssh = [f for f in ssh_findings if "0.0.0.0/0" in str(f.evidence)]
    assert len(open_ssh) == 0


@mock_aws
def test_ec2_scanner_result_structure():
    from app.scanners.aws.ec2 import AWSEC2Scanner
    from app.scanners.base import ScannerResult

    scanner = AWSEC2Scanner({"aws_regions": ["us-east-1"]})
    result = asyncio.run(scanner.scan())

    assert isinstance(result, ScannerResult)
    assert result.provider == "aws"
    assert result.service == "ec2"
    assert result.duration_seconds >= 0
