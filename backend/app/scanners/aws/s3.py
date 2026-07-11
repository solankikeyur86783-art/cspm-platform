import time
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult
from app.core.logging import logger


class AWSS3Scanner(BaseScanner):
    provider = "aws"
    service = "s3"

    def __init__(self, account_config: Dict[str, Any]):
        super().__init__(account_config)
        self.s3 = boto3.client("s3", region_name=account_config.get("region", "us-east-1"))
        self.s3_control = boto3.client("s3control", region_name=account_config.get("region", "us-east-1"))

    async def scan(self) -> ScannerResult:
        start = time.time()
        logger.info("Starting AWS S3 scan")

        await self._check_account_public_access_block()
        await self._check_buckets()

        return self.build_result(duration=time.time() - start)

    async def _check_account_public_access_block(self) -> None:
        """CIS 2.1.5 — Account-level S3 public access block."""
        try:
            import boto3
            sts = boto3.client("sts")
            account_id = sts.get_caller_identity()["Account"]
            config = self.s3_control.get_public_access_block(AccountId=account_id)
            pab = config["PublicAccessBlockConfiguration"]
            for setting in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"):
                if not pab.get(setting, False):
                    self.add_finding(ScanFinding(
                        rule_id="CIS-S3-2.1.5",
                        rule_name=f"Account-level S3 public access block '{setting}' not enabled",
                        severity="critical",
                        resource_id=f"account:{account_id}",
                        resource_type="s3:account_public_access_block",
                        cloud_provider="aws",
                        evidence={"setting": setting, "value": pab.get(setting)},
                        cvss_score=9.1,
                        cis_benchmark_refs=["CIS AWS 2.1.5"],
                        mitre_attack_techniques=["T1530"],
                        remediation_steps=f"Enable {setting} at account level.",
                        remediation_code=f"aws s3control put-public-access-block --account-id {account_id} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                    ))
        except ClientError as exc:
            self.add_error(f"Account public access block: {exc}")

    async def _check_buckets(self) -> None:
        try:
            buckets = self.s3.list_buckets()["Buckets"]
        except ClientError as exc:
            self.add_error(f"list_buckets: {exc}")
            return

        for bucket in buckets:
            name = bucket["Name"]
            self.resources_scanned += 1

            await self._check_bucket_public_access(name)
            await self._check_bucket_encryption(name)
            await self._check_bucket_versioning(name)
            await self._check_bucket_logging(name)
            await self._check_bucket_policy(name)
            await self._check_bucket_mfa_delete(name)

    async def _check_bucket_public_access(self, name: str) -> None:
        """CIS 2.1.1 — Bucket-level public access block."""
        try:
            pab = self.s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            for setting in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"):
                if not pab.get(setting, False):
                    self.add_finding(ScanFinding(
                        rule_id="CIS-S3-2.1.1",
                        rule_name=f"S3 bucket public access block '{setting}' not enabled",
                        severity="high",
                        resource_id=f"arn:aws:s3:::{name}",
                        resource_name=name,
                        resource_type="s3:bucket",
                        cloud_provider="aws",
                        evidence={"bucket": name, "setting": setting},
                        cvss_score=8.5,
                        cis_benchmark_refs=["CIS AWS 2.1.1"],
                        mitre_attack_techniques=["T1530"],
                        remediation_steps=f"Enable {setting} on bucket {name}.",
                        remediation_code=f"aws s3api put-public-access-block --bucket {name} --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
                    ))
        except ClientError as exc:
            if "NoSuchPublicAccessBlockConfiguration" in str(exc):
                self.add_finding(ScanFinding(
                    rule_id="CIS-S3-2.1.1",
                    rule_name="S3 bucket has no public access block configuration",
                    severity="high",
                    resource_id=f"arn:aws:s3:::{name}",
                    resource_name=name,
                    resource_type="s3:bucket",
                    cloud_provider="aws",
                    cvss_score=8.5,
                    cis_benchmark_refs=["CIS AWS 2.1.1"],
                    remediation_steps=f"Configure public access block on bucket {name}.",
                ))

    async def _check_bucket_encryption(self, name: str) -> None:
        """CIS 2.1.2 — Ensure S3 buckets are encrypted at rest."""
        try:
            enc = self.s3.get_bucket_encryption(Bucket=name)
            rules = enc.get("ServerSideEncryptionConfiguration", {}).get("Rules", [])
            if not rules:
                raise ValueError("No encryption rules")
        except (ClientError, ValueError):
            self.add_finding(ScanFinding(
                rule_id="CIS-S3-2.1.2",
                rule_name="S3 bucket does not have server-side encryption enabled",
                severity="high",
                resource_id=f"arn:aws:s3:::{name}",
                resource_name=name,
                resource_type="s3:bucket",
                cloud_provider="aws",
                cvss_score=7.5,
                cis_benchmark_refs=["CIS AWS 2.1.2"],
                remediation_steps=f"Enable SSE-S3 or SSE-KMS encryption on bucket {name}.",
                remediation_code=f'aws s3api put-bucket-encryption --bucket {name} --server-side-encryption-configuration \'{{"Rules":[{{"ApplyServerSideEncryptionByDefault":{{"SSEAlgorithm":"AES256"}}}}]}}\'',
            ))

    async def _check_bucket_versioning(self, name: str) -> None:
        """CIS 2.1.3 — Enable versioning for S3 buckets."""
        try:
            ver = self.s3.get_bucket_versioning(Bucket=name)
            if ver.get("Status") != "Enabled":
                self.add_finding(ScanFinding(
                    rule_id="CIS-S3-2.1.3",
                    rule_name="S3 bucket versioning is not enabled",
                    severity="medium",
                    resource_id=f"arn:aws:s3:::{name}",
                    resource_name=name,
                    resource_type="s3:bucket",
                    cloud_provider="aws",
                    evidence={"versioning_status": ver.get("Status", "Disabled")},
                    cvss_score=5.0,
                    cis_benchmark_refs=["CIS AWS 2.1.3"],
                    remediation_steps=f"Enable versioning on bucket {name}.",
                    remediation_code=f"aws s3api put-bucket-versioning --bucket {name} --versioning-configuration Status=Enabled",
                ))
        except ClientError as exc:
            self.add_error(f"Bucket versioning {name}: {exc}")

    async def _check_bucket_logging(self, name: str) -> None:
        """CIS 2.6 — S3 bucket access logging."""
        try:
            logging_cfg = self.s3.get_bucket_logging(Bucket=name)
            if "LoggingEnabled" not in logging_cfg:
                self.add_finding(ScanFinding(
                    rule_id="CIS-S3-2.6",
                    rule_name="S3 bucket access logging is not enabled",
                    severity="low",
                    resource_id=f"arn:aws:s3:::{name}",
                    resource_name=name,
                    resource_type="s3:bucket",
                    cloud_provider="aws",
                    cvss_score=3.5,
                    cis_benchmark_refs=["CIS AWS 2.6"],
                    mitre_attack_techniques=["T1530"],
                    remediation_steps=f"Enable access logging on bucket {name}.",
                ))
        except ClientError as exc:
            self.add_error(f"Bucket logging {name}: {exc}")

    async def _check_bucket_policy(self, name: str) -> None:
        """Check for wildcard principal in bucket policy."""
        try:
            import json
            policy_str = self.s3.get_bucket_policy(Bucket=name)["Policy"]
            policy = json.loads(policy_str)
            for stmt in policy.get("Statement", []):
                principal = stmt.get("Principal", "")
                effect = stmt.get("Effect", "")
                if effect == "Allow" and (principal == "*" or principal == {"AWS": "*"}):
                    self.add_finding(ScanFinding(
                        rule_id="S3-POLICY-001",
                        rule_name="S3 bucket policy allows public access (wildcard principal)",
                        severity="critical",
                        resource_id=f"arn:aws:s3:::{name}",
                        resource_name=name,
                        resource_type="s3:bucket",
                        cloud_provider="aws",
                        evidence={"statement": stmt},
                        cvss_score=9.5,
                        mitre_attack_techniques=["T1530"],
                        remediation_steps=f"Remove wildcard principal from bucket policy on {name}.",
                    ))
                    break
        except ClientError as exc:
            if "NoSuchBucketPolicy" not in str(exc):
                self.add_error(f"Bucket policy {name}: {exc}")

    async def _check_bucket_mfa_delete(self, name: str) -> None:
        """CIS 2.1.3 — MFA delete for versioned buckets."""
        try:
            ver = self.s3.get_bucket_versioning(Bucket=name)
            if ver.get("Status") == "Enabled" and ver.get("MFADelete") != "Enabled":
                self.add_finding(ScanFinding(
                    rule_id="CIS-S3-2.1.3-MFA",
                    rule_name="S3 bucket versioning enabled but MFA delete not enabled",
                    severity="medium",
                    resource_id=f"arn:aws:s3:::{name}",
                    resource_name=name,
                    resource_type="s3:bucket",
                    cloud_provider="aws",
                    cvss_score=5.0,
                    cis_benchmark_refs=["CIS AWS 2.1.3"],
                    remediation_steps=f"Enable MFA delete on bucket {name} to prevent accidental deletions.",
                ))
        except ClientError:
            pass
