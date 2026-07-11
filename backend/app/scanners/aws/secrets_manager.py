"""
AWS Secrets Manager scanner — adds Scenario 9 (rotation disabled).
Drop this file into: backend/app/scanners/aws/secrets_manager.py
Then add SecretsManagerScanner to backend/app/scanners/aws/__init__.py
"""

import time
from typing import Any, Dict, List
from datetime import datetime, timezone

import boto3
from botocore.exceptions import ClientError

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult
from app.core.logging import logger


class AWSSecretsManagerScanner(BaseScanner):
    provider = "aws"
    service = "secretsmanager"

    def __init__(self, account_config: Dict[str, Any]):
        super().__init__(account_config)
        self.regions: List[str] = account_config.get("aws_regions") or ["us-east-1"]

    async def scan(self) -> ScannerResult:
        start = time.time()
        logger.info(f"Starting AWS Secrets Manager scan across regions: {self.regions}")

        for region in self.regions:
            self.sm = boto3.client("secretsmanager", region_name=region)
            await self._check_secrets(region)

        return self.build_result(duration=time.time() - start)

    async def _check_secrets(self, region: str) -> None:
        try:
            paginator = self.sm.get_paginator("list_secrets")
            for page in paginator.paginate():
                for secret in page["SecretList"]:
                    self.resources_scanned += 1
                    secret_id  = secret["ARN"]
                    secret_name = secret["Name"]

                    # ── Scenario 9: Rotation disabled ────────────────
                    rotation_enabled = secret.get("RotationEnabled", False)
                    if not rotation_enabled:
                        self.add_finding(ScanFinding(
                            rule_id="SM-ROTATION-001",
                            rule_name="Secrets Manager secret does not have rotation enabled",
                            rule_description=(
                                "Automatic rotation reduces the risk of credential exposure. "
                                "Without rotation, a compromised secret remains valid indefinitely."
                            ),
                            severity="medium",
                            resource_id=secret_id,
                            resource_name=secret_name,
                            resource_type="secretsmanager:secret",
                            cloud_provider="aws",
                            region=region,
                            evidence={
                                "secret_name": secret_name,
                                "rotation_enabled": False,
                                "last_rotated": str(secret.get("LastRotatedDate", "Never")),
                            },
                            cvss_score=5.5,
                            mitre_attack_techniques=["T1552", "T1552.001"],
                            compliance_frameworks=["SOC 2 — CC6", "HIPAA — 164.312(a)(2)(iv)"],
                            remediation_steps=(
                                f"Enable rotation for secret '{secret_name}'. "
                                "Use AWS Lambda rotation function or Secrets Manager built-in rotation."
                            ),
                            remediation_code=(
                                f"aws secretsmanager rotate-secret "
                                f"--secret-id {secret_name} "
                                f"--rotation-lambda-arn arn:aws:lambda:{region}:ACCOUNT:function:rotate-fn "
                                f"--rotation-rules AutomaticallyAfterDays=30"
                            ),
                        ))

                    # ── Stale secret (not rotated in 90+ days) ───────
                    last_changed = secret.get("LastChangedDate")
                    if last_changed:
                        age_days = (datetime.now(timezone.utc) - last_changed).days
                        if age_days > 90:
                            self.add_finding(ScanFinding(
                                rule_id="SM-ROTATION-002",
                                rule_name=f"Secret has not been rotated in {age_days} days",
                                severity="medium",
                                resource_id=secret_id,
                                resource_name=secret_name,
                                resource_type="secretsmanager:secret",
                                cloud_provider="aws",
                                region=region,
                                evidence={
                                    "secret_name": secret_name,
                                    "age_days": age_days,
                                    "last_changed": str(last_changed)[:10],
                                },
                                cvss_score=5.0,
                                mitre_attack_techniques=["T1552"],
                                remediation_steps=f"Rotate the secret '{secret_name}' — last changed {age_days} days ago.",
                            ))

                    # ── Secret not used in 90+ days ───────────────────
                    last_accessed = secret.get("LastAccessedDate")
                    if last_accessed:
                        unused_days = (datetime.now(timezone.utc) - last_accessed).days
                        if unused_days > 90:
                            self.add_finding(ScanFinding(
                                rule_id="SM-UNUSED-001",
                                rule_name=f"Secret has not been accessed in {unused_days} days",
                                severity="low",
                                resource_id=secret_id,
                                resource_name=secret_name,
                                resource_type="secretsmanager:secret",
                                cloud_provider="aws",
                                region=region,
                                evidence={
                                    "unused_days": unused_days,
                                    "last_accessed": str(last_accessed)[:10],
                                },
                                cvss_score=2.5,
                                remediation_steps=f"Delete or archive unused secret '{secret_name}'.",
                                remediation_code=f"aws secretsmanager delete-secret --secret-id {secret_name} --recovery-window-in-days 7",
                            ))

        except ClientError as exc:
            self.add_error(f"Secrets Manager [{region}]: {exc}")
