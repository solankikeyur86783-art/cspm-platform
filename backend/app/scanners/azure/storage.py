import time
from typing import Any, Dict

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult
from app.core.logging import logger


class AzureStorageScanner(BaseScanner):
    provider = "azure"
    service = "storage"

    def __init__(self, account_config: Dict[str, Any]):
        super().__init__(account_config)
        self.subscription_id = account_config.get("azure_subscription_id", "")

    async def scan(self) -> ScannerResult:
        start = time.time()
        logger.info(f"Starting Azure Storage scan for subscription {self.subscription_id}")

        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.storage import StorageManagementClient

            creds = DefaultAzureCredential()
            self.storage_client = StorageManagementClient(creds, self.subscription_id)

            await self._check_storage_accounts()

        except ImportError:
            self.add_error("azure-mgmt-storage not installed")
        except Exception as exc:
            self.add_error(f"Azure Storage scan failed: {exc}")

        return self.build_result(duration=time.time() - start)

    async def _check_storage_accounts(self) -> None:
        try:
            accounts = list(self.storage_client.storage_accounts.list())
        except Exception as exc:
            self.add_error(f"list storage accounts: {exc}")
            return

        for account in accounts:
            self.resources_scanned += 1
            name = account.name
            account_id = account.id

            # Public blob access
            if account.allow_blob_public_access:
                self.add_finding(ScanFinding(
                    rule_id="CIS-AZ-3.7",
                    rule_name="Azure storage account allows public blob access",
                    severity="high",
                    resource_id=account_id,
                    resource_name=name,
                    resource_type="azure:storage_account",
                    cloud_provider="azure",
                    evidence={"location": account.location, "kind": str(account.kind)},
                    cvss_score=8.5,
                    cis_benchmark_refs=["CIS Azure 3.7"],
                    mitre_attack_techniques=["T1530"],
                    remediation_steps=f"Disable public blob access on storage account {name}.",
                    remediation_code=f"az storage account update --name {name} --allow-blob-public-access false",
                ))

            # HTTPS only
            if not account.enable_https_traffic_only:
                self.add_finding(ScanFinding(
                    rule_id="CIS-AZ-3.1",
                    rule_name="Azure storage account allows HTTP traffic",
                    severity="high",
                    resource_id=account_id,
                    resource_name=name,
                    resource_type="azure:storage_account",
                    cloud_provider="azure",
                    cvss_score=7.5,
                    cis_benchmark_refs=["CIS Azure 3.1"],
                    mitre_attack_techniques=["T1557"],
                    remediation_steps=f"Enable HTTPS-only traffic on storage account {name}.",
                    remediation_code=f"az storage account update --name {name} --https-only true",
                ))

            # Minimum TLS version
            if str(account.minimum_tls_version) != "TLS1_2":
                self.add_finding(ScanFinding(
                    rule_id="CIS-AZ-3.2",
                    rule_name="Azure storage account minimum TLS version is below 1.2",
                    severity="medium",
                    resource_id=account_id,
                    resource_name=name,
                    resource_type="azure:storage_account",
                    cloud_provider="azure",
                    evidence={"tls_version": str(account.minimum_tls_version)},
                    cvss_score=6.0,
                    cis_benchmark_refs=["CIS Azure 3.2"],
                    remediation_steps=f"Set minimum TLS version to 1.2 on {name}.",
                    remediation_code=f"az storage account update --name {name} --min-tls-version TLS1_2",
                ))

            # Soft delete for blobs
            try:
                blob_props = self.storage_client.blob_services.get_service_properties(
                    account.id.split("/resourceGroups/")[1].split("/")[0],
                    name,
                )
                delete_retention = blob_props.delete_retention_policy
                if not delete_retention or not delete_retention.enabled:
                    self.add_finding(ScanFinding(
                        rule_id="CIS-AZ-3.8",
                        rule_name="Azure storage account blob soft delete is not enabled",
                        severity="medium",
                        resource_id=account_id,
                        resource_name=name,
                        resource_type="azure:storage_account",
                        cloud_provider="azure",
                        cvss_score=4.5,
                        cis_benchmark_refs=["CIS Azure 3.8"],
                        remediation_steps=f"Enable blob soft delete with 7+ day retention on {name}.",
                        remediation_code=f"az storage account blob-service-properties update --account-name {name} --enable-delete-retention true --delete-retention-days 7",
                    ))
            except Exception:
                pass

            # Infrastructure encryption
            if not (account.encryption and account.encryption.require_infrastructure_encryption):
                self.add_finding(ScanFinding(
                    rule_id="CIS-AZ-3.3",
                    rule_name="Azure storage account infrastructure encryption not enabled",
                    severity="medium",
                    resource_id=account_id,
                    resource_name=name,
                    resource_type="azure:storage_account",
                    cloud_provider="azure",
                    cvss_score=5.0,
                    cis_benchmark_refs=["CIS Azure 3.3"],
                    remediation_steps=f"Enable infrastructure encryption on storage account {name} (must be set at creation).",
                ))
