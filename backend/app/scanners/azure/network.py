import time
from typing import Any, Dict

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult
from app.core.logging import logger


class AzureNetworkScanner(BaseScanner):
    provider = "azure"
    service = "network"

    def __init__(self, account_config: Dict[str, Any]):
        super().__init__(account_config)
        self.subscription_id = account_config.get("azure_subscription_id", "")

    async def scan(self) -> ScannerResult:
        start = time.time()
        logger.info(f"Starting Azure Network scan for subscription {self.subscription_id}")

        try:
            from azure.identity import DefaultAzureCredential
            from azure.mgmt.network import NetworkManagementClient

            creds = DefaultAzureCredential()
            self.network_client = NetworkManagementClient(creds, self.subscription_id)

            await self._check_nsgs()
            await self._check_network_watchers()

        except ImportError:
            self.add_error("azure-mgmt-network not installed")
        except Exception as exc:
            self.add_error(f"Azure Network scan failed: {exc}")

        return self.build_result(duration=time.time() - start)

    async def _check_nsgs(self) -> None:
        """CIS Azure 6.x — NSG rules should not allow unrestricted inbound access."""
        DANGEROUS_PORTS = {22: "SSH", 3389: "RDP", 1433: "MSSQL", 3306: "MySQL"}

        try:
            nsgs = list(self.network_client.network_security_groups.list_all())
            for nsg in nsgs:
                self.resources_scanned += 1
                nsg_name = nsg.name or ""
                nsg_id = nsg.id or ""

                for rule in (nsg.security_rules or []):
                    if rule.direction != "Inbound":
                        continue
                    if rule.access != "Allow":
                        continue

                    source_prefix = rule.source_address_prefix or ""
                    is_open = source_prefix in ("*", "Internet", "Any", "0.0.0.0/0")
                    if not is_open:
                        continue

                    dest_port = rule.destination_port_range or ""

                    for port, service_name in DANGEROUS_PORTS.items():
                        if str(port) in dest_port or dest_port == "*":
                            severity = "critical" if port in (22, 3389) else "high"
                            rule_id = "CIS-AZ-6.1" if port == 3389 else "CIS-AZ-6.2" if port == 22 else "AZ-NSG-001"
                            self.add_finding(ScanFinding(
                                rule_id=rule_id,
                                rule_name=f"NSG rule allows unrestricted {service_name} (port {port}) from Internet",
                                severity=severity,
                                resource_id=nsg_id,
                                resource_name=nsg_name,
                                resource_type="azure:network_security_group",
                                cloud_provider="azure",
                                evidence={
                                    "rule_name": rule.name,
                                    "source": source_prefix,
                                    "dest_port": dest_port,
                                    "priority": rule.priority,
                                },
                                cvss_score=9.8,
                                cis_benchmark_refs=[rule_id],
                                mitre_attack_techniques=["T1190", "T1021"],
                                remediation_steps=f"Restrict inbound {service_name} in NSG '{nsg_name}' rule '{rule.name}' to specific IP ranges. Use Azure Bastion for RDP/SSH.",
                            ))

                    # All traffic
                    if dest_port == "*" and source_prefix in ("*", "Internet"):
                        self.add_finding(ScanFinding(
                            rule_id="AZ-NSG-002",
                            rule_name="NSG rule allows all inbound traffic from Internet",
                            severity="critical",
                            resource_id=nsg_id,
                            resource_name=nsg_name,
                            resource_type="azure:network_security_group",
                            cloud_provider="azure",
                            evidence={"rule_name": rule.name, "priority": rule.priority},
                            cvss_score=10.0,
                            mitre_attack_techniques=["T1190"],
                            remediation_steps=f"Remove or restrict the all-traffic allow rule in NSG '{nsg_name}'.",
                        ))

        except Exception as exc:
            self.add_error(f"NSG check: {exc}")

    async def _check_network_watchers(self) -> None:
        """CIS Azure 6.5 — Network Watcher should be enabled in all regions."""
        try:
            watchers = list(self.network_client.network_watchers.list_all())
            if not watchers:
                self.add_finding(ScanFinding(
                    rule_id="CIS-AZ-6.5",
                    rule_name="Azure Network Watcher is not enabled",
                    severity="medium",
                    resource_id=f"/subscriptions/{self.subscription_id}/networkWatchers",
                    resource_type="azure:network_watcher",
                    cloud_provider="azure",
                    cvss_score=5.0,
                    cis_benchmark_refs=["CIS Azure 6.5"],
                    mitre_attack_techniques=["T1040"],
                    remediation_steps="Enable Network Watcher in all Azure regions used.",
                    remediation_code="az network watcher configure --locations eastus westus --enabled true",
                ))
            self.resources_scanned += len(watchers)
        except Exception as exc:
            self.add_error(f"Network Watcher check: {exc}")
