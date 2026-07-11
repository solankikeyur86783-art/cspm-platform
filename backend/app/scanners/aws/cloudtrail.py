import time
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult
from app.core.logging import logger


class AWSCloudTrailScanner(BaseScanner):
    provider = "aws"
    service = "cloudtrail"

    def __init__(self, account_config: Dict[str, Any]):
        super().__init__(account_config)
        self.ct = boto3.client("cloudtrail", region_name=account_config.get("region", "us-east-1"))
        self.cloudwatch = boto3.client("cloudwatch", region_name=account_config.get("region", "us-east-1"))
        self.logs = boto3.client("logs", region_name=account_config.get("region", "us-east-1"))

    async def scan(self) -> ScannerResult:
        start = time.time()
        logger.info("Starting AWS CloudTrail scan")

        trails = await self._get_trails()
        if not trails:
            self.add_finding(ScanFinding(
                rule_id="CIS-CT-2.1",
                rule_name="No CloudTrail trails configured",
                severity="critical",
                resource_id="cloudtrail",
                resource_type="cloudtrail:trail",
                cloud_provider="aws",
                cvss_score=9.0,
                cis_benchmark_refs=["CIS AWS 2.1"],
                mitre_attack_techniques=["T1562.008"],
                remediation_steps="Create a multi-region CloudTrail trail.",
                remediation_code="aws cloudtrail create-trail --name cspm-audit-trail --s3-bucket-name your-ct-bucket --is-multi-region-trail --enable-log-file-validation",
            ))
            return self.build_result(duration=time.time() - start)

        for trail in trails:
            await self._check_trail(trail)

        await self._check_cloudwatch_alarms()

        return self.build_result(duration=time.time() - start)

    async def _get_trails(self):
        try:
            return self.ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        except ClientError as exc:
            self.add_error(f"describe_trails: {exc}")
            return []

    async def _check_trail(self, trail: dict) -> None:
        name = trail["Name"]
        arn = trail.get("TrailARN", name)
        self.resources_scanned += 1

        # CIS 2.1 — Multi-region
        if not trail.get("IsMultiRegionTrail"):
            self.add_finding(ScanFinding(
                rule_id="CIS-CT-2.1",
                rule_name="CloudTrail trail is not multi-region",
                severity="high",
                resource_id=arn,
                resource_name=name,
                resource_type="cloudtrail:trail",
                cloud_provider="aws",
                cvss_score=7.0,
                cis_benchmark_refs=["CIS AWS 2.1"],
                mitre_attack_techniques=["T1562.008"],
                remediation_steps=f"Update trail {name} to be multi-region.",
                remediation_code=f"aws cloudtrail update-trail --name {name} --is-multi-region-trail",
            ))

        # CIS 2.2 — Log file validation
        if not trail.get("LogFileValidationEnabled"):
            self.add_finding(ScanFinding(
                rule_id="CIS-CT-2.2",
                rule_name="CloudTrail log file validation not enabled",
                severity="medium",
                resource_id=arn,
                resource_name=name,
                resource_type="cloudtrail:trail",
                cloud_provider="aws",
                cvss_score=5.5,
                cis_benchmark_refs=["CIS AWS 2.2"],
                remediation_steps=f"Enable log file validation on trail {name}.",
                remediation_code=f"aws cloudtrail update-trail --name {name} --enable-log-file-validation",
            ))

        # CIS 2.4 — CloudWatch Logs integration
        if not trail.get("CloudWatchLogsLogGroupArn"):
            self.add_finding(ScanFinding(
                rule_id="CIS-CT-2.4",
                rule_name="CloudTrail not integrated with CloudWatch Logs",
                severity="medium",
                resource_id=arn,
                resource_name=name,
                resource_type="cloudtrail:trail",
                cloud_provider="aws",
                cvss_score=5.0,
                cis_benchmark_refs=["CIS AWS 2.4"],
                remediation_steps=f"Configure CloudWatch Logs for trail {name}.",
            ))

        # Check trail status
        try:
            status = self.ct.get_trail_status(Name=arn)
            if not status.get("IsLogging"):
                self.add_finding(ScanFinding(
                    rule_id="CIS-CT-2.1-LOGGING",
                    rule_name="CloudTrail trail logging is disabled",
                    severity="critical",
                    resource_id=arn,
                    resource_name=name,
                    resource_type="cloudtrail:trail",
                    cloud_provider="aws",
                    cvss_score=9.0,
                    cis_benchmark_refs=["CIS AWS 2.1"],
                    mitre_attack_techniques=["T1562.008"],
                    remediation_steps=f"Enable logging on trail {name}.",
                    remediation_code=f"aws cloudtrail start-logging --name {name}",
                ))
        except ClientError as exc:
            self.add_error(f"Trail status {name}: {exc}")

    async def _check_cloudwatch_alarms(self) -> None:
        """CIS 3.x — Metric filters and alarms for critical API calls."""
        cis_alarms = [
            ("CIS-CW-3.1", "Unauthorized API calls alarm", "$.errorCode = \"*UnauthorizedAccess*\""),
            ("CIS-CW-3.2", "Console signin without MFA alarm", "$.eventName = \"ConsoleLogin\" && $.additionalEventData.MFAUsed != \"Yes\""),
            ("CIS-CW-3.3", "Root account usage alarm", "$.userIdentity.type = \"Root\""),
            ("CIS-CW-3.4", "IAM policy changes alarm", "$.eventName = \"DeleteGroupPolicy\""),
        ]

        try:
            alarms = self.cloudwatch.describe_alarms()
            alarm_names = {a["AlarmName"].lower() for a in alarms.get("MetricAlarms", [])}

            for rule_id, rule_name, _ in cis_alarms:
                matched = any(
                    keyword in a_name for a_name in alarm_names
                    for keyword in rule_name.lower().split()[:2]
                )
                if not matched:
                    self.add_finding(ScanFinding(
                        rule_id=rule_id,
                        rule_name=f"Missing CloudWatch alarm: {rule_name}",
                        severity="medium",
                        resource_id="cloudwatch:alarms",
                        resource_type="cloudwatch:alarm",
                        cloud_provider="aws",
                        cvss_score=5.0,
                        cis_benchmark_refs=[f"CIS AWS {rule_id.split('-')[2]}"],
                        mitre_attack_techniques=["T1562"],
                        remediation_steps=f"Create a CloudWatch metric filter and alarm for: {rule_name}",
                    ))
        except ClientError as exc:
            self.add_error(f"CloudWatch alarms check: {exc}")
