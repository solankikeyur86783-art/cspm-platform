import time
from typing import Any, Dict

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult
from app.core.logging import logger


class GCPStorageScanner(BaseScanner):
    provider = "gcp"
    service = "storage"

    def __init__(self, account_config: Dict[str, Any]):
        super().__init__(account_config)
        self.project_id = account_config.get("gcp_project_id", "")

    async def scan(self) -> ScannerResult:
        start = time.time()
        logger.info(f"Starting GCP Storage scan for project {self.project_id}")

        try:
            from google.cloud import storage
            self.client = storage.Client(project=self.project_id)
            await self._check_buckets()
        except ImportError:
            self.add_error("google-cloud-storage not installed")
        except Exception as exc:
            self.add_error(f"GCP Storage scan failed: {exc}")

        return self.build_result(duration=time.time() - start)

    async def _check_buckets(self) -> None:
        try:
            buckets = list(self.client.list_buckets())
        except Exception as exc:
            self.add_error(f"list_buckets: {exc}")
            return

        for bucket in buckets:
            self.resources_scanned += 1
            name = bucket.name

            await self._check_public_access(bucket)
            await self._check_uniform_access(bucket)
            await self._check_logging(bucket)
            await self._check_versioning(bucket)
            await self._check_retention(bucket)

    async def _check_public_access(self, bucket) -> None:
        """CIS GCP 5.1 — No public IAM members on buckets."""
        try:
            policy = bucket.get_iam_policy()
            for binding in policy.bindings:
                members = binding.get("members", [])
                if "allUsers" in members or "allAuthenticatedUsers" in members:
                    public_member = "allUsers" if "allUsers" in members else "allAuthenticatedUsers"
                    self.add_finding(ScanFinding(
                        rule_id="CIS-GCS-5.1",
                        rule_name=f"GCS bucket is publicly accessible via IAM ({public_member})",
                        severity="critical",
                        resource_id=f"gs://{bucket.name}",
                        resource_name=bucket.name,
                        resource_type="gcp:gcs_bucket",
                        cloud_provider="gcp",
                        evidence={"role": binding.get("role"), "public_member": public_member},
                        cvss_score=9.8,
                        cis_benchmark_refs=["CIS GCP 5.1"],
                        mitre_attack_techniques=["T1530"],
                        remediation_steps=f"Remove {public_member} from IAM policy on bucket {bucket.name}.",
                        remediation_code=f"gsutil iam ch -d {public_member} gs://{bucket.name}",
                    ))
        except Exception as exc:
            self.add_error(f"Bucket public access {bucket.name}: {exc}")

    async def _check_uniform_access(self, bucket) -> None:
        """CIS GCP 5.2 — Uniform bucket-level access should be enabled."""
        try:
            bucket.reload()
            if not bucket.iam_configuration.uniform_bucket_level_access_enabled:
                self.add_finding(ScanFinding(
                    rule_id="CIS-GCS-5.2",
                    rule_name="GCS bucket does not have uniform bucket-level access enabled",
                    severity="medium",
                    resource_id=f"gs://{bucket.name}",
                    resource_name=bucket.name,
                    resource_type="gcp:gcs_bucket",
                    cloud_provider="gcp",
                    cvss_score=5.5,
                    cis_benchmark_refs=["CIS GCP 5.2"],
                    remediation_steps=f"Enable uniform bucket-level access on {bucket.name}.",
                    remediation_code=f"gsutil uniformbucketlevelaccess set on gs://{bucket.name}",
                ))
        except Exception as exc:
            self.add_error(f"Uniform access check {bucket.name}: {exc}")

    async def _check_logging(self, bucket) -> None:
        """CIS GCP 5.3 — Enable logging on GCS buckets."""
        try:
            bucket.reload()
            if not bucket.logging:
                self.add_finding(ScanFinding(
                    rule_id="CIS-GCS-5.3",
                    rule_name="GCS bucket access logging is not enabled",
                    severity="low",
                    resource_id=f"gs://{bucket.name}",
                    resource_name=bucket.name,
                    resource_type="gcp:gcs_bucket",
                    cloud_provider="gcp",
                    cvss_score=3.5,
                    cis_benchmark_refs=["CIS GCP 5.3"],
                    remediation_steps=f"Enable access logging on bucket {bucket.name}.",
                    remediation_code=f"gsutil logging set on -b gs://YOUR-LOG-BUCKET gs://{bucket.name}",
                ))
        except Exception as exc:
            self.add_error(f"Logging check {bucket.name}: {exc}")

    async def _check_versioning(self, bucket) -> None:
        """Versioning should be enabled for critical buckets."""
        try:
            bucket.reload()
            if not bucket.versioning_enabled:
                self.add_finding(ScanFinding(
                    rule_id="GCS-VERSION-001",
                    rule_name="GCS bucket versioning is not enabled",
                    severity="low",
                    resource_id=f"gs://{bucket.name}",
                    resource_name=bucket.name,
                    resource_type="gcp:gcs_bucket",
                    cloud_provider="gcp",
                    cvss_score=3.0,
                    remediation_steps=f"Enable versioning on bucket {bucket.name}.",
                    remediation_code=f"gsutil versioning set on gs://{bucket.name}",
                ))
        except Exception as exc:
            self.add_error(f"Versioning check {bucket.name}: {exc}")

    async def _check_retention(self, bucket) -> None:
        """Check for retention policy."""
        try:
            bucket.reload()
            if not bucket.retention_policy:
                self.add_finding(ScanFinding(
                    rule_id="GCS-RETENTION-001",
                    rule_name="GCS bucket has no retention policy configured",
                    severity="info",
                    resource_id=f"gs://{bucket.name}",
                    resource_name=bucket.name,
                    resource_type="gcp:gcs_bucket",
                    cloud_provider="gcp",
                    cvss_score=2.0,
                    remediation_steps=f"Consider setting a retention policy on bucket {bucket.name} for compliance.",
                ))
        except Exception as exc:
            self.add_error(f"Retention check {bucket.name}: {exc}")
