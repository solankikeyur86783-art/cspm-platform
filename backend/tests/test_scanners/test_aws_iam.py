import pytest
import asyncio
import boto3
from moto import mock_aws


@mock_aws
def test_iam_scanner_no_findings_on_compliant_account():
    """A clean IAM setup should produce zero critical findings."""
    from app.scanners.aws.iam import AWSIAMScanner

    # Create a compliant setup
    iam = boto3.client("iam", region_name="us-east-1")
    iam.update_account_password_policy(
        MinimumPasswordLength=14,
        RequireUppercaseCharacters=True,
        RequireLowercaseCharacters=True,
        RequireNumbers=True,
        RequireSymbols=True,
        MaxPasswordAge=90,
    )

    scanner = AWSIAMScanner({"region": "us-east-1"})
    from unittest.mock import patch
    with patch.object(scanner.iam, "get_account_summary", return_value={"SummaryMap": {"AccountMFAEnabled": 1}}):
        result = asyncio.run(scanner.scan())

    critical = [f for f in result.findings if f.severity == "critical"]
    assert len(critical) == 0, f"Expected no critical findings, got: {[f.rule_id for f in critical]}"


@mock_aws
def test_iam_scanner_detects_weak_password_policy():
    """Weak password policy should trigger CIS-IAM findings."""
    from app.scanners.aws.iam import AWSIAMScanner

    iam = boto3.client("iam", region_name="us-east-1")
    iam.update_account_password_policy(
        MinimumPasswordLength=6,  # Too short
        RequireUppercaseCharacters=False,
        RequireLowercaseCharacters=False,
        RequireNumbers=False,
        RequireSymbols=False,
        MaxPasswordAge=365,  # Too long
    )

    scanner = AWSIAMScanner({"region": "us-east-1"})
    result = asyncio.run(scanner.scan())

    rule_ids = [f.rule_id for f in result.findings]
    assert "CIS-IAM-1.8" in rule_ids, "Should flag minimum password length"
    assert "CIS-IAM-1.9" in rule_ids, "Should flag missing uppercase requirement"


@mock_aws
def test_iam_scanner_detects_no_password_policy():
    """Missing password policy should trigger CIS-IAM-1.8."""
    from app.scanners.aws.iam import AWSIAMScanner

    scanner = AWSIAMScanner({"region": "us-east-1"})
    result = asyncio.run(scanner.scan())

    rule_ids = [f.rule_id for f in result.findings]
    assert "CIS-IAM-1.8" in rule_ids


@mock_aws
def test_iam_scanner_detects_admin_policy_on_user():
    """Admin policy attached directly to user should be flagged."""
    from app.scanners.aws.iam import AWSIAMScanner

    iam = boto3.client("iam", region_name="us-east-1")
    iam.create_user(UserName="bad-user")
    policy = iam.create_policy(
        PolicyName="AdministratorAccess",
        PolicyDocument='{"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}'
    )
    iam.attach_user_policy(
        UserName="bad-user",
        PolicyArn=policy["Policy"]["Arn"],
    )

    scanner = AWSIAMScanner({"region": "us-east-1"})
    result = asyncio.run(scanner.scan())

    rule_ids = [f.rule_id for f in result.findings]
    assert "CIS-IAM-1.16" in rule_ids, "Should detect admin policy on user"


@mock_aws
def test_iam_scanner_returns_scanner_result_structure():
    """Scanner result should have correct structure."""
    from app.scanners.aws.iam import AWSIAMScanner
    from app.scanners.base import ScannerResult

    scanner = AWSIAMScanner({"region": "us-east-1"})
    result = asyncio.run(scanner.scan())

    assert isinstance(result, ScannerResult)
    assert result.provider == "aws"
    assert result.service == "iam"
    assert isinstance(result.findings, list)
    assert isinstance(result.errors, list)
    assert result.duration_seconds >= 0
