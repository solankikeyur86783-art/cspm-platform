import time
from typing import Any, Dict

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult
from app.core.logging import logger


class GCPComputeScanner(BaseScanner):
    provider = "gcp"
    service = "compute"

    def __init__(self, account_config: Dict[str, Any]):
        super().__init__(account_config)
        self.project_id = account_config.get("gcp_project_id", "")

    async def scan(self) -> ScannerResult:
        start = time.time()
        logger.info(f"Starting GCP Compute scan for project {self.project_id}")

        try:
            from googleapiclient import discovery
            from google.auth import default

            creds, _ = default()
            self.compute = discovery.build("compute", "v1", credentials=creds)

            await self._check_instances()
            await self._check_firewall_rules()
            await self._check_project_metadata()
            await self._check_disks()

        except ImportError:
            self.add_error("google-api-python-client not installed")
        except Exception as exc:
            self.add_error(f"GCP Compute scan failed: {exc}")

        return self.build_result(duration=time.time() - start)

    async def _check_instances(self) -> None:
        """CIS GCP 4.x — Compute instance checks."""
        try:
            request = self.compute.instances().aggregatedList(project=self.project_id)
            while request is not None:
                response = request.execute()
                for zone, zone_data in response.get("items", {}).items():
                    for instance in zone_data.get("instances", []):
                        self.resources_scanned += 1
                        name = instance["name"]
                        zone_name = zone.split("/")[-1]

                        # CIS 4.6 — OS Login
                        metadata = instance.get("metadata", {}).get("items", [])
                        metadata_dict = {m["key"]: m["value"] for m in metadata}
                        if metadata_dict.get("enable-oslogin", "").lower() != "true":
                            self.add_finding(ScanFinding(
                                rule_id="CIS-GCP-4.4",
                                rule_name="GCE instance does not have OS Login enabled",
                                severity="medium",
                                resource_id=instance["selfLink"],
                                resource_name=name,
                                resource_type="gcp:compute_instance",
                                cloud_provider="gcp",
                                region=zone_name,
                                evidence={"zone": zone_name},
                                cvss_score=5.5,
                                cis_benchmark_refs=["CIS GCP 4.4"],
                                mitre_attack_techniques=["T1078"],
                                remediation_steps=f"Enable OS Login on instance {name}.",
                                remediation_code=f"gcloud compute instances add-metadata {name} --zone={zone_name} --metadata enable-oslogin=TRUE --project={self.project_id}",
                            ))

                        # CIS 4.5 — Serial port access
                        if metadata_dict.get("serial-port-enable", "0") == "1":
                            self.add_finding(ScanFinding(
                                rule_id="CIS-GCP-4.5",
                                rule_name="GCE instance has serial port access enabled",
                                severity="medium",
                                resource_id=instance["selfLink"],
                                resource_name=name,
                                resource_type="gcp:compute_instance",
                                cloud_provider="gcp",
                                region=zone_name,
                                evidence={"zone": zone_name},
                                cvss_score=5.0,
                                cis_benchmark_refs=["CIS GCP 4.5"],
                                mitre_attack_techniques=["T1021"],
                                remediation_steps=f"Disable serial port access on instance {name}.",
                                remediation_code=f"gcloud compute instances add-metadata {name} --zone={zone_name} --metadata serial-port-enable=0 --project={self.project_id}",
                            ))

                        # Check for public IP (ephemeral or static)
                        for interface in instance.get("networkInterfaces", []):
                            for access_config in interface.get("accessConfigs", []):
                                if access_config.get("natIP") or access_config.get("type") == "ONE_TO_ONE_NAT":
                                    self.add_finding(ScanFinding(
                                        rule_id="GCP-COMPUTE-001",
                                        rule_name="GCE instance has a public external IP address",
                                        severity="medium",
                                        resource_id=instance["selfLink"],
                                        resource_name=name,
                                        resource_type="gcp:compute_instance",
                                        cloud_provider="gcp",
                                        region=zone_name,
                                        evidence={
                                            "nat_ip": access_config.get("natIP"),
                                            "access_type": access_config.get("type"),
                                        },
                                        cvss_score=5.5,
                                        mitre_attack_techniques=["T1190"],
                                        remediation_steps=f"Remove external IP from instance {name}. Use Cloud NAT or IAP for outbound/inbound access.",
                                    ))
                                    break

                        # CIS 4.2 — Shielded VM
                        shielded_config = instance.get("shieldedInstanceConfig", {})
                        if not shielded_config.get("enableVtpm") or not shielded_config.get("enableIntegrityMonitoring"):
                            self.add_finding(ScanFinding(
                                rule_id="CIS-GCP-4.8",
                                rule_name="GCE instance does not have Shielded VM features enabled",
                                severity="low",
                                resource_id=instance["selfLink"],
                                resource_name=name,
                                resource_type="gcp:compute_instance",
                                cloud_provider="gcp",
                                region=zone_name,
                                evidence={
                                    "enable_vtpm": shielded_config.get("enableVtpm"),
                                    "enable_integrity_monitoring": shielded_config.get("enableIntegrityMonitoring"),
                                },
                                cvss_score=3.5,
                                cis_benchmark_refs=["CIS GCP 4.8"],
                                remediation_steps=f"Enable vTPM and Integrity Monitoring on instance {name}.",
                                remediation_code=f"gcloud compute instances update {name} --zone={zone_name} --shielded-vtpm --shielded-integrity-monitoring --project={self.project_id}",
                            ))

                request = self.compute.instances().aggregatedList_next(
                    previous_request=request, previous_response=response
                )
        except Exception as exc:
            self.add_error(f"GCE instances check: {exc}")

    async def _check_firewall_rules(self) -> None:
        """CIS GCP 3.6/3.7 — No unrestricted SSH/RDP from 0.0.0.0/0."""
        try:
            rules = self.compute.firewalls().list(project=self.project_id).execute()
            for rule in rules.get("items", []):
                self.resources_scanned += 1
                if rule.get("direction") != "INGRESS":
                    continue
                if rule.get("disabled"):
                    continue

                source_ranges = rule.get("sourceRanges", [])
                is_open = "0.0.0.0/0" in source_ranges or "::/0" in source_ranges

                if not is_open:
                    continue

                allowed = rule.get("allowed", [])
                for allow in allowed:
                    protocol = allow.get("IPProtocol", "")
                    ports = allow.get("ports", [])

                    # SSH (22)
                    if protocol in ("tcp", "all") and (not ports or "22" in ports or "0-65535" in ports):
                        self.add_finding(ScanFinding(
                            rule_id="CIS-GCP-3.6",
                            rule_name="Firewall rule allows unrestricted SSH (port 22) from 0.0.0.0/0",
                            severity="critical",
                            resource_id=rule["selfLink"],
                            resource_name=rule["name"],
                            resource_type="gcp:firewall_rule",
                            cloud_provider="gcp",
                            evidence={"rule_name": rule["name"], "priority": rule.get("priority")},
                            cvss_score=9.8,
                            cis_benchmark_refs=["CIS GCP 3.6"],
                            mitre_attack_techniques=["T1190", "T1021.004"],
                            remediation_steps=f"Restrict SSH access in firewall rule '{rule['name']}' to specific IP ranges. Use Cloud IAP instead.",
                            remediation_code=f"gcloud compute firewall-rules delete {rule['name']} --project={self.project_id}",
                        ))

                    # RDP (3389)
                    if protocol in ("tcp", "all") and (not ports or "3389" in ports or "0-65535" in ports):
                        self.add_finding(ScanFinding(
                            rule_id="CIS-GCP-3.7",
                            rule_name="Firewall rule allows unrestricted RDP (port 3389) from 0.0.0.0/0",
                            severity="critical",
                            resource_id=rule["selfLink"],
                            resource_name=rule["name"],
                            resource_type="gcp:firewall_rule",
                            cloud_provider="gcp",
                            evidence={"rule_name": rule["name"], "priority": rule.get("priority")},
                            cvss_score=9.8,
                            cis_benchmark_refs=["CIS GCP 3.7"],
                            mitre_attack_techniques=["T1190", "T1021.001"],
                            remediation_steps=f"Restrict RDP access in firewall rule '{rule['name']}' to specific IP ranges.",
                            remediation_code=f"gcloud compute firewall-rules delete {rule['name']} --project={self.project_id}",
                        ))

                    # All traffic
                    if protocol == "all" and not ports:
                        self.add_finding(ScanFinding(
                            rule_id="GCP-FW-001",
                            rule_name="Firewall rule allows all traffic from 0.0.0.0/0",
                            severity="critical",
                            resource_id=rule["selfLink"],
                            resource_name=rule["name"],
                            resource_type="gcp:firewall_rule",
                            cloud_provider="gcp",
                            evidence={"rule_name": rule["name"]},
                            cvss_score=10.0,
                            mitre_attack_techniques=["T1190"],
                            remediation_steps=f"Delete or restrict firewall rule '{rule['name']}'.",
                        ))

        except Exception as exc:
            self.add_error(f"Firewall rules check: {exc}")

    async def _check_project_metadata(self) -> None:
        """CIS GCP 4.3/4.4 — Project-level metadata checks."""
        try:
            project = self.compute.projects().get(project=self.project_id).execute()
            metadata_items = project.get("commonInstanceMetadata", {}).get("items", [])
            metadata = {m["key"]: m["value"] for m in metadata_items}

            # OS Login at project level
            if metadata.get("enable-oslogin", "").lower() != "true":
                self.add_finding(ScanFinding(
                    rule_id="CIS-GCP-4.4-PROJECT",
                    rule_name="GCP project does not have OS Login enabled by default",
                    severity="medium",
                    resource_id=f"projects/{self.project_id}",
                    resource_name=self.project_id,
                    resource_type="gcp:project",
                    cloud_provider="gcp",
                    cvss_score=5.0,
                    cis_benchmark_refs=["CIS GCP 4.4"],
                    remediation_steps="Enable OS Login at project level.",
                    remediation_code=f"gcloud compute project-info add-metadata --metadata enable-oslogin=TRUE --project={self.project_id}",
                ))

        except Exception as exc:
            self.add_error(f"Project metadata check: {exc}")

    async def _check_disks(self) -> None:
        """Check for unencrypted persistent disks."""
        try:
            request = self.compute.disks().aggregatedList(project=self.project_id)
            while request is not None:
                response = request.execute()
                for zone, zone_data in response.get("items", {}).items():
                    for disk in zone_data.get("disks", []):
                        self.resources_scanned += 1
                        # Disks without customer-managed keys use Google-managed keys (OK)
                        # but disks without ANY encryption are the concern
                        if not disk.get("diskEncryptionKey") and not disk.get("sourceSnapshotEncryptionKey"):
                            # This is actually fine (Google encrypts by default), flag only if CMEK is required
                            pass  # Would add finding if CMEK policy is required

                request = self.compute.disks().aggregatedList_next(
                    previous_request=request, previous_response=response
                )
        except Exception as exc:
            self.add_error(f"Disks check: {exc}")
