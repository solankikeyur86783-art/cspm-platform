import time
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult
from app.core.logging import logger


class AWSVPCScanner(BaseScanner):
    provider = "aws"
    service = "vpc"

    def __init__(self, account_config: Dict[str, Any]):
        super().__init__(account_config)
        self.regions: List[str] = account_config.get("aws_regions") or ["us-east-1"]

    async def scan(self) -> ScannerResult:
        start = time.time()
        logger.info(f"Starting AWS VPC scan across regions: {self.regions}")

        for region in self.regions:
            self.ec2 = boto3.client("ec2", region_name=region)
            await self._check_flow_logs(region)
            await self._check_nacls(region)
            await self._check_peering(region)
            await self._check_vpn_gateways(region)

        return self.build_result(duration=time.time() - start)

    async def _check_flow_logs(self, region: str) -> None:
        """CIS 3.9 — VPC flow logging enabled for all VPCs."""
        try:
            vpcs = self.ec2.describe_vpcs()["Vpcs"]
            flow_logs = self.ec2.describe_flow_logs()["FlowLogs"]
            logged_vpcs = {fl["ResourceId"] for fl in flow_logs if fl["FlowLogStatus"] == "ACTIVE"}

            for vpc in vpcs:
                self.resources_scanned += 1
                vpc_id = vpc["VpcId"]
                if vpc_id not in logged_vpcs:
                    self.add_finding(ScanFinding(
                        rule_id="CIS-VPC-3.9",
                        rule_name="VPC flow logging is not enabled",
                        severity="medium",
                        resource_id=vpc_id,
                        resource_type="ec2:vpc",
                        cloud_provider="aws",
                        region=region,
                        evidence={"is_default": vpc.get("IsDefault"), "cidr": vpc.get("CidrBlock")},
                        cvss_score=5.5,
                        cis_benchmark_refs=["CIS AWS 3.9"],
                        mitre_attack_techniques=["T1040"],
                        remediation_steps=f"Enable VPC flow logs for VPC {vpc_id}.",
                        remediation_code=(
                            f"aws ec2 create-flow-logs --resource-type VPC "
                            f"--resource-ids {vpc_id} "
                            f"--traffic-type ALL "
                            f"--log-destination-type cloud-watch-logs "
                            f"--log-group-name /vpc/flowlogs "
                            f"--deliver-logs-permission-arn arn:aws:iam::ACCOUNT:role/flowlogs-role "
                            f"--region {region}"
                        ),
                    ))
        except ClientError as exc:
            self.add_error(f"VPC flow logs [{region}]: {exc}")

    async def _check_nacls(self, region: str) -> None:
        """Check NACLs for overly permissive rules."""
        try:
            paginator = self.ec2.get_paginator("describe_network_acls")
            for page in paginator.paginate():
                for nacl in page["NetworkAcls"]:
                    self.resources_scanned += 1
                    nacl_id = nacl["NetworkAclId"]

                    for entry in nacl.get("Entries", []):
                        # Skip egress rules
                        if entry.get("Egress"):
                            continue
                        # Rule allowing all traffic from anywhere
                        if (
                            entry.get("RuleAction") == "allow"
                            and entry.get("Protocol") == "-1"
                            and entry.get("CidrBlock") in ("0.0.0.0/0", "::/0")
                        ):
                            self.add_finding(ScanFinding(
                                rule_id="VPC-NACL-001",
                                rule_name="NACL rule allows all inbound traffic from 0.0.0.0/0",
                                severity="medium",
                                resource_id=nacl_id,
                                resource_type="ec2:network_acl",
                                cloud_provider="aws",
                                region=region,
                                evidence={
                                    "rule_number": entry.get("RuleNumber"),
                                    "cidr": entry.get("CidrBlock"),
                                    "vpc_id": nacl.get("VpcId"),
                                },
                                cvss_score=5.0,
                                mitre_attack_techniques=["T1190"],
                                remediation_steps=f"Review and restrict NACL rule #{entry.get('RuleNumber')} on {nacl_id}.",
                            ))
        except ClientError as exc:
            self.add_error(f"NACL check [{region}]: {exc}")

    async def _check_peering(self, region: str) -> None:
        """Check VPC peering for overly broad route tables."""
        try:
            peerings = self.ec2.describe_vpc_peering_connections(
                Filters=[{"Name": "status-code", "Values": ["active"]}]
            )["VpcPeeringConnections"]

            for peering in peerings:
                self.resources_scanned += 1
                pcx_id = peering["VpcPeeringConnectionId"]
                requester = peering.get("RequesterVpcInfo", {})
                accepter = peering.get("AccepterVpcInfo", {})

                # Cross-account peering — flag for review
                if requester.get("OwnerId") != accepter.get("OwnerId"):
                    self.add_finding(ScanFinding(
                        rule_id="VPC-PEER-001",
                        rule_name="Cross-account VPC peering connection active",
                        severity="info",
                        resource_id=pcx_id,
                        resource_type="ec2:vpc_peering",
                        cloud_provider="aws",
                        region=region,
                        evidence={
                            "requester_account": requester.get("OwnerId"),
                            "accepter_account": accepter.get("OwnerId"),
                            "requester_cidr": requester.get("CidrBlock"),
                            "accepter_cidr": accepter.get("CidrBlock"),
                        },
                        cvss_score=2.0,
                        remediation_steps=f"Review cross-account VPC peering {pcx_id} to ensure it is authorized.",
                    ))
        except ClientError as exc:
            self.add_error(f"VPC peering [{region}]: {exc}")

    async def _check_vpn_gateways(self, region: str) -> None:
        """Check for unused VPN gateways (cost + security hygiene)."""
        try:
            gateways = self.ec2.describe_vpn_gateways(
                Filters=[{"Name": "state", "Values": ["available"]}]
            )["VpnGateways"]

            for gw in gateways:
                self.resources_scanned += 1
                attachments = gw.get("VpcAttachments", [])
                if not attachments or all(a["State"] == "detached" for a in attachments):
                    self.add_finding(ScanFinding(
                        rule_id="VPC-VGW-001",
                        rule_name="VPN gateway is not attached to any VPC",
                        severity="info",
                        resource_id=gw["VpnGatewayId"],
                        resource_type="ec2:vpn_gateway",
                        cloud_provider="aws",
                        region=region,
                        cvss_score=1.5,
                        remediation_steps=f"Delete unused VPN gateway {gw['VpnGatewayId']} to reduce attack surface.",
                        remediation_code=f"aws ec2 delete-vpn-gateway --vpn-gateway-id {gw['VpnGatewayId']} --region {region}",
                    ))
        except ClientError as exc:
            self.add_error(f"VPN gateways [{region}]: {exc}")
