import pytest
import asyncio
import boto3
from moto import mock_aws


@mock_aws
def test_vpc_scanner_detects_no_flow_logs():
    """VPC without flow logs should trigger CIS-VPC-3.9."""
    from app.scanners.aws.vpc import AWSVPCScanner

    # Default VPC exists in moto but flow logs are not enabled
    scanner = AWSVPCScanner({"aws_regions": ["us-east-1"]})
    result = asyncio.run(scanner.scan())

    rule_ids = [f.rule_id for f in result.findings]
    assert "CIS-VPC-3.9" in rule_ids


@mock_aws
def test_vpc_scanner_result_structure():
    from app.scanners.aws.vpc import AWSVPCScanner
    from app.scanners.base import ScannerResult

    scanner = AWSVPCScanner({"aws_regions": ["us-east-1"]})
    result = asyncio.run(scanner.scan())

    assert isinstance(result, ScannerResult)
    assert result.provider == "aws"
    assert result.service == "vpc"
    assert result.resources_scanned >= 0


@mock_aws
def test_vpc_scanner_detects_permissive_nacl():
    """NACL rule allowing all traffic from 0.0.0.0/0 should be flagged."""
    from app.scanners.aws.vpc import AWSVPCScanner

    ec2 = boto3.client("ec2", region_name="us-east-1")
    vpcs = ec2.describe_vpcs()["Vpcs"]
    vpc_id = vpcs[0]["VpcId"]

    # Get the default NACL
    nacls = ec2.describe_network_acls(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
    )["NetworkAcls"]

    if nacls:
        nacl_id = nacls[0]["NetworkAclId"]
        # Add an allow-all inbound rule
        ec2.create_network_acl_entry(
            NetworkAclId=nacl_id,
            RuleNumber=50,
            Protocol="-1",
            RuleAction="allow",
            Egress=False,
            CidrBlock="0.0.0.0/0",
        )

    scanner = AWSVPCScanner({"aws_regions": ["us-east-1"]})
    result = asyncio.run(scanner.scan())

    rule_ids = [f.rule_id for f in result.findings]
    assert "VPC-NACL-001" in rule_ids
