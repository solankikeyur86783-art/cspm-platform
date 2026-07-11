import time
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult
from app.core.logging import logger


class AWSIAMScanner(BaseScanner):
    provider = "aws"
    service = "iam"

    def __init__(self, account_config: Dict[str, Any]):
        super().__init__(account_config)
        self.iam = boto3.client(
            "iam",
            region_name=account_config.get("region", "us-east-1"),
        )

    async def scan(self) -> ScannerResult:
        start = time.time()
        logger.info("Starting AWS IAM scan")

        await self._check_root_account_usage()
        await self._check_mfa_on_root()
        await self._check_hardware_mfa_on_root()
        await self._check_access_key_rotation()
        await self._check_inactive_users()
        await self._check_password_policy()
        await self._check_admin_policies()
        await self._check_unused_credentials()
        await self._check_support_role()

        return self.build_result(duration=time.time() - start)

    async def _check_root_account_usage(self) -> None:
        """CIS 1.1 — Avoid the use of the root account."""
        try:
            report = self.iam.get_credential_report()
            import csv, io
            reader = csv.DictReader(io.StringIO(report["Content"].decode()))
            for row in reader:
                if row["user"] == "<root_account>":
                    self.resources_scanned += 1
                    if row.get("access_key_1_last_used_date", "N/A") != "N/A":
                        self.add_finding(ScanFinding(
                            rule_id="CIS-IAM-1.1",
                            rule_name="Root account has been recently used",
                            rule_description="The root account should not be used for day-to-day tasks.",
                            severity="critical",
                            resource_id="root",
                            resource_type="iam:root_account",
                            cloud_provider="aws",
                            evidence={"last_used": row.get("access_key_1_last_used_date")},
                            cvss_score=9.0,
                            cis_benchmark_refs=["CIS AWS 1.1"],
                            mitre_attack_techniques=["T1078.004"],
                            remediation_steps="Do not use the root account for daily tasks. Create individual IAM users.",
                            remediation_code="aws iam create-user --user-name admin-user",
                        ))
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ReportNotPresent":
                try:
                    self.iam.generate_credential_report()
                except Exception:
                    pass
            self.add_error(f"IAM credential report: {exc}")

    async def _check_mfa_on_root(self) -> None:
        """CIS 1.5 — Ensure MFA is enabled for the root account."""
        try:
            summary = self.iam.get_account_summary()
            self.resources_scanned += 1
            if not summary["SummaryMap"].get("AccountMFAEnabled", 0):
                self.add_finding(ScanFinding(
                    rule_id="CIS-IAM-1.5",
                    rule_name="MFA not enabled on root account",
                    rule_description="Root account does not have MFA enabled.",
                    severity="critical",
                    resource_id="root",
                    resource_type="iam:root_account",
                    cloud_provider="aws",
                    cvss_score=9.5,
                    cis_benchmark_refs=["CIS AWS 1.5"],
                    mitre_attack_techniques=["T1078.004"],
                    remediation_steps="Enable MFA on the root account via IAM Console > Security Credentials.",
                ))
        except ClientError as exc:
            self.add_error(f"MFA check: {exc}")

    async def _check_hardware_mfa_on_root(self) -> None:
        """CIS 1.6 — Hardware MFA for root."""
        try:
            virtual_devices = self.iam.list_virtual_mfa_devices(AssignmentStatus="Assigned")
            root_virtual = any(
                "root" in d.get("SerialNumber", "") for d in virtual_devices.get("VirtualMFADevices", [])
            )
            if root_virtual:
                self.add_finding(ScanFinding(
                    rule_id="CIS-IAM-1.6",
                    rule_name="Root account uses virtual MFA instead of hardware MFA",
                    severity="high",
                    resource_id="root",
                    resource_type="iam:root_account",
                    cloud_provider="aws",
                    cvss_score=7.5,
                    cis_benchmark_refs=["CIS AWS 1.6"],
                    remediation_steps="Replace virtual MFA with a hardware MFA device for the root account.",
                ))
        except ClientError as exc:
            self.add_error(f"Hardware MFA check: {exc}")

    async def _check_access_key_rotation(self) -> None:
        """CIS 1.14 — Ensure access keys are rotated every 90 days."""
        from datetime import datetime, timezone
        try:
            paginator = self.iam.get_paginator("list_users")
            async_pages = paginator.paginate()
            for page in async_pages:
                for user in page["Users"]:
                    self.resources_scanned += 1
                    keys = self.iam.list_access_keys(UserName=user["UserName"])
                    for key in keys["AccessKeyMetadata"]:
                        if key["Status"] != "Active":
                            continue
                        created = key["CreateDate"]
                        age_days = (datetime.now(timezone.utc) - created).days
                        if age_days > 90:
                            self.add_finding(ScanFinding(
                                rule_id="CIS-IAM-1.14",
                                rule_name="Access key not rotated within 90 days",
                                severity="high",
                                resource_id=key["AccessKeyId"],
                                resource_name=user["UserName"],
                                resource_type="iam:access_key",
                                cloud_provider="aws",
                                evidence={"user": user["UserName"], "age_days": age_days, "key_id": key["AccessKeyId"]},
                                cvss_score=6.5,
                                cis_benchmark_refs=["CIS AWS 1.14"],
                                mitre_attack_techniques=["T1528"],
                                remediation_steps=f"Rotate access key for user {user['UserName']}.",
                                remediation_code=f"aws iam create-access-key --user-name {user['UserName']}\naws iam delete-access-key --user-name {user['UserName']} --access-key-id {key['AccessKeyId']}",
                            ))
        except ClientError as exc:
            self.add_error(f"Key rotation check: {exc}")

    async def _check_inactive_users(self) -> None:
        """CIS 1.15 — Remove unused IAM credentials after 90 days."""
        from datetime import datetime, timezone
        try:
            report = self.iam.get_credential_report()
            import csv, io
            reader = csv.DictReader(io.StringIO(report["Content"].decode()))
            for row in reader:
                if row["user"] == "<root_account>":
                    continue
                last_used_str = row.get("password_last_used", "no_information")
                if last_used_str in ("no_information", "N/A", ""):
                    continue
                last_used = datetime.fromisoformat(last_used_str.replace("Z", "+00:00"))
                days_inactive = (datetime.now(timezone.utc) - last_used).days
                if days_inactive > 90:
                    self.add_finding(ScanFinding(
                        rule_id="CIS-IAM-1.15",
                        rule_name="IAM user inactive for more than 90 days",
                        severity="medium",
                        resource_id=row["arn"],
                        resource_name=row["user"],
                        resource_type="iam:user",
                        cloud_provider="aws",
                        evidence={"days_inactive": days_inactive, "last_used": last_used_str},
                        cvss_score=5.5,
                        cis_benchmark_refs=["CIS AWS 1.15"],
                        mitre_attack_techniques=["T1078"],
                        remediation_steps=f"Disable or delete IAM user '{row['user']}' — inactive for {days_inactive} days.",
                        remediation_code=f"aws iam update-login-profile --user-name {row['user']} --password-reset-required\n# Or delete: aws iam delete-login-profile --user-name {row['user']}",
                    ))
        except ClientError as exc:
            self.add_error(f"Inactive users check: {exc}")

    async def _check_password_policy(self) -> None:
        """CIS 1.8-1.13 — Password policy requirements."""
        try:
            policy = self.iam.get_account_password_policy()["PasswordPolicy"]
            self.resources_scanned += 1
            checks = [
                ("MinimumPasswordLength", 14, "CIS-IAM-1.8", "Password minimum length less than 14", "medium", 4.0, "CIS AWS 1.8"),
                ("RequireUppercaseCharacters", True, "CIS-IAM-1.9", "Password policy does not require uppercase", "medium", 4.0, "CIS AWS 1.9"),
                ("RequireLowercaseCharacters", True, "CIS-IAM-1.10", "Password policy does not require lowercase", "medium", 4.0, "CIS AWS 1.10"),
                ("RequireNumbers", True, "CIS-IAM-1.11", "Password policy does not require numbers", "medium", 4.0, "CIS AWS 1.11"),
                ("RequireSymbols", True, "CIS-IAM-1.12", "Password policy does not require symbols", "medium", 4.0, "CIS AWS 1.12"),
                ("MaxPasswordAge", 90, "CIS-IAM-1.13", "Password expiration greater than 90 days", "medium", 4.0, "CIS AWS 1.13"),
            ]
            for key, threshold, rule_id, name, severity, cvss, cis_ref in checks:
                val = policy.get(key)
                fail = False
                if isinstance(threshold, bool):
                    fail = not val
                elif key == "MaxPasswordAge":
                    fail = (val or 999) > threshold
                else:
                    fail = (val or 0) < threshold

                if fail:
                    self.add_finding(ScanFinding(
                        rule_id=rule_id,
                        rule_name=name,
                        severity=severity,
                        resource_id="password-policy",
                        resource_type="iam:password_policy",
                        cloud_provider="aws",
                        evidence={key: val},
                        cvss_score=cvss,
                        cis_benchmark_refs=[cis_ref],
                        remediation_steps=f"Update account password policy: {name}",
                    ))
        except self.iam.exceptions.NoSuchEntityException:
            self.add_finding(ScanFinding(
                rule_id="CIS-IAM-1.8",
                rule_name="No IAM account password policy configured",
                severity="high",
                resource_id="password-policy",
                resource_type="iam:password_policy",
                cloud_provider="aws",
                cvss_score=7.0,
                cis_benchmark_refs=["CIS AWS 1.8-1.13"],
                remediation_steps="Create an IAM account password policy.",
                remediation_code="aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols --max-password-age 90",
            ))
        except ClientError as exc:
            self.add_error(f"Password policy check: {exc}")

    async def _check_admin_policies(self) -> None:
        """CIS 1.16 — Ensure IAM policies are attached only to groups or roles."""
        try:
            paginator = self.iam.get_paginator("list_users")
            for page in paginator.paginate():
                for user in page["Users"]:
                    policies = self.iam.list_attached_user_policies(UserName=user["UserName"])
                    for policy in policies["AttachedPolicies"]:
                        if "AdministratorAccess" in policy["PolicyName"]:
                            self.add_finding(ScanFinding(
                                rule_id="CIS-IAM-1.16",
                                rule_name="AdministratorAccess policy attached directly to user",
                                severity="high",
                                resource_id=user["Arn"],
                                resource_name=user["UserName"],
                                resource_type="iam:user",
                                cloud_provider="aws",
                                evidence={"policy": policy["PolicyName"], "user": user["UserName"]},
                                cvss_score=8.0,
                                cis_benchmark_refs=["CIS AWS 1.16"],
                                mitre_attack_techniques=["T1078.004"],
                                remediation_steps=f"Detach AdministratorAccess from user {user['UserName']} and assign via group.",
                                remediation_code=f"aws iam detach-user-policy --user-name {user['UserName']} --policy-arn {policy['PolicyArn']}",
                            ))
        except ClientError as exc:
            self.add_error(f"Admin policy check: {exc}")

    async def _check_unused_credentials(self) -> None:
        """CIS 1.20 — Ensure access keys are not created during initial setup."""
        try:
            from datetime import datetime, timezone
            report = self.iam.get_credential_report()
            import csv, io
            reader = csv.DictReader(io.StringIO(report["Content"].decode()))
            for row in reader:
                if row["user"] == "<root_account>":
                    continue
                for key_num in ("1", "2"):
                    if row.get(f"access_key_{key_num}_active") == "true":
                        last_used = row.get(f"access_key_{key_num}_last_used_date", "N/A")
                        if last_used == "N/A":
                            self.add_finding(ScanFinding(
                                rule_id="CIS-IAM-1.20",
                                rule_name="Active access key has never been used",
                                severity="low",
                                resource_id=row["arn"],
                                resource_name=row["user"],
                                resource_type="iam:access_key",
                                cloud_provider="aws",
                                evidence={"user": row["user"], "key_number": key_num},
                                cvss_score=3.0,
                                cis_benchmark_refs=["CIS AWS 1.20"],
                                remediation_steps=f"Delete unused access key for {row['user']}.",
                            ))
        except ClientError as exc:
            self.add_error(f"Unused credentials check: {exc}")

    async def _check_support_role(self) -> None:
        """CIS 1.17 — Ensure a support role has been created."""
        try:
            roles = self.iam.list_roles()
            has_support_role = any(
                "support" in r["RoleName"].lower() for r in roles.get("Roles", [])
            )
            if not has_support_role:
                self.add_finding(ScanFinding(
                    rule_id="CIS-IAM-1.17",
                    rule_name="No support role created for incident management",
                    severity="low",
                    resource_id="iam:roles",
                    resource_type="iam:role",
                    cloud_provider="aws",
                    cvss_score=2.5,
                    cis_benchmark_refs=["CIS AWS 1.17"],
                    remediation_steps="Create a support role with AWSSupportAccess policy.",
                ))
        except ClientError as exc:
            self.add_error(f"Support role check: {exc}")
