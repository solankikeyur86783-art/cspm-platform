import time
from typing import Any, Dict
from datetime import datetime, timezone

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult
from app.core.logging import logger


class GCPIAMScanner(BaseScanner):
    provider = "gcp"
    service = "iam"

    def __init__(self, account_config: Dict[str, Any]):
        super().__init__(account_config)
        self.project_id = account_config.get("gcp_project_id", "")

    async def scan(self) -> ScannerResult:
        start = time.time()
        logger.info(f"Starting GCP IAM scan for project {self.project_id}")

        try:
            from googleapiclient import discovery
            from google.auth import default

            creds, _ = default()
            self.crm = discovery.build("cloudresourcemanager", "v1", credentials=creds)
            self.iam_service = discovery.build("iam", "v1", credentials=creds)

            await self._check_primitive_roles()
            await self._check_service_account_keys()
            await self._check_service_account_admin()
            await self._check_kms_separation()

        except ImportError:
            self.add_error("google-cloud libraries not installed")
        except Exception as exc:
            self.add_error(f"GCP IAM scan failed: {exc}")

        return self.build_result(duration=time.time() - start)

    async def _check_primitive_roles(self) -> None:
        """CIS GCP 1.4 — Don't use primitive roles (Owner/Editor/Viewer) at project level."""
        try:
            policy = self.crm.projects().getIamPolicy(
                resource=self.project_id, body={}
            ).execute()

            primitive_roles = {"roles/owner", "roles/editor", "roles/viewer"}
            for binding in policy.get("bindings", []):
                if binding["role"] in primitive_roles:
                    self.resources_scanned += 1
                    for member in binding["members"]:
                        if member.startswith("user:") or member.startswith("serviceAccount:"):
                            self.add_finding(ScanFinding(
                                rule_id="CIS-GCP-IAM-1.4",
                                rule_name=f"Primitive IAM role '{binding['role']}' assigned at project level",
                                rule_description="Primitive roles grant broad access and should not be used.",
                                severity="high",
                                resource_id=f"{self.project_id}/iam/{member}",
                                resource_name=member,
                                resource_type="gcp:iam_binding",
                                cloud_provider="gcp",
                                evidence={"role": binding["role"], "member": member, "project": self.project_id},
                                cvss_score=8.0,
                                cis_benchmark_refs=["CIS GCP 1.4"],
                                mitre_attack_techniques=["T1078.004"],
                                remediation_steps=f"Replace primitive role '{binding['role']}' with a predefined or custom role for {member}.",
                            ))
        except Exception as exc:
            self.add_error(f"Primitive roles check: {exc}")

    async def _check_service_account_keys(self) -> None:
        """CIS GCP 1.6 — Service account keys should be rotated within 90 days."""
        try:
            service_accounts = self.iam_service.projects().serviceAccounts().list(
                name=f"projects/{self.project_id}"
            ).execute()

            for sa in service_accounts.get("accounts", []):
                self.resources_scanned += 1
                sa_email = sa["email"]
                sa_name = sa["name"]

                keys = self.iam_service.projects().serviceAccounts().keys().list(
                    name=sa_name,
                    keyTypes=["USER_MANAGED"],
                ).execute()

                for key in keys.get("keys", []):
                    created_str = key.get("validAfterTime", "")
                    if created_str:
                        created = datetime.fromisoformat(created_str.replace("Z", "+00:00"))
                        age_days = (datetime.now(timezone.utc) - created).days

                        if age_days > 90:
                            self.add_finding(ScanFinding(
                                rule_id="CIS-GCP-IAM-1.6",
                                rule_name="Service account key not rotated in 90+ days",
                                severity="high",
                                resource_id=key["name"],
                                resource_name=sa_email,
                                resource_type="gcp:service_account_key",
                                cloud_provider="gcp",
                                evidence={"age_days": age_days, "key_id": key["name"].split("/")[-1]},
                                cvss_score=7.0,
                                cis_benchmark_refs=["CIS GCP 1.6"],
                                mitre_attack_techniques=["T1528"],
                                remediation_steps=f"Rotate service account key for {sa_email}.",
                            ))

                    # Check if key is not used
                    if not key.get("validBeforeTime"):
                        self.add_finding(ScanFinding(
                            rule_id="CIS-GCP-IAM-1.7",
                            rule_name="Service account has unused external keys",
                            severity="medium",
                            resource_id=key["name"],
                            resource_name=sa_email,
                            resource_type="gcp:service_account_key",
                            cloud_provider="gcp",
                            cvss_score=5.0,
                            cis_benchmark_refs=["CIS GCP 1.7"],
                            remediation_steps=f"Delete unused service account keys for {sa_email}.",
                        ))
        except Exception as exc:
            self.add_error(f"Service account keys check: {exc}")

    async def _check_service_account_admin(self) -> None:
        """CIS GCP 1.5 — Service accounts should not have admin privileges."""
        try:
            policy = self.crm.projects().getIamPolicy(
                resource=self.project_id, body={}
            ).execute()

            admin_roles = {"roles/owner", "roles/editor", "roles/iam.serviceAccountAdmin"}
            for binding in policy.get("bindings", []):
                if binding["role"] in admin_roles:
                    for member in binding["members"]:
                        if member.startswith("serviceAccount:"):
                            self.add_finding(ScanFinding(
                                rule_id="CIS-GCP-IAM-1.5",
                                rule_name=f"Service account has admin role: {binding['role']}",
                                severity="critical",
                                resource_id=f"{self.project_id}/iam/{member}",
                                resource_name=member,
                                resource_type="gcp:iam_binding",
                                cloud_provider="gcp",
                                evidence={"role": binding["role"], "service_account": member},
                                cvss_score=9.0,
                                cis_benchmark_refs=["CIS GCP 1.5"],
                                mitre_attack_techniques=["T1078.004"],
                                remediation_steps=f"Remove admin role from service account {member}. Use least-privilege custom roles.",
                            ))
        except Exception as exc:
            self.add_error(f"Service account admin check: {exc}")

    async def _check_kms_separation(self) -> None:
        """CIS GCP 1.9 — Separation of duties for KMS."""
        try:
            policy = self.crm.projects().getIamPolicy(
                resource=self.project_id, body={}
            ).execute()

            kms_admin_members = set()
            kms_encrypter_members = set()

            for binding in policy.get("bindings", []):
                if binding["role"] == "roles/cloudkms.admin":
                    kms_admin_members.update(binding["members"])
                if binding["role"] in ("roles/cloudkms.cryptoKeyEncrypterDecrypter",):
                    kms_encrypter_members.update(binding["members"])

            overlap = kms_admin_members & kms_encrypter_members
            for member in overlap:
                self.add_finding(ScanFinding(
                    rule_id="CIS-GCP-IAM-1.9",
                    rule_name="Member has both KMS Admin and KMS CryptoKey roles (no separation of duties)",
                    severity="high",
                    resource_id=f"{self.project_id}/iam/{member}",
                    resource_name=member,
                    resource_type="gcp:iam_binding",
                    cloud_provider="gcp",
                    evidence={"member": member},
                    cvss_score=7.5,
                    cis_benchmark_refs=["CIS GCP 1.9"],
                    remediation_steps=f"Remove either KMS Admin or KMS Encrypter role from {member}.",
                ))
        except Exception as exc:
            self.add_error(f"KMS separation check: {exc}")
