import time
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult
from app.core.logging import logger


class AWSEC2Scanner(BaseScanner):
    provider = "aws"
    service = "ec2"

    def __init__(self, account_config: Dict[str, Any]):
        super().__init__(account_config)
        self.regions: List[str] = account_config.get("aws_regions") or ["us-east-1"]

    async def scan(self) -> ScannerResult:
        start = time.time()
        logger.info(f"Starting AWS EC2 scan across regions: {self.regions}")

        for region in self.regions:
            self.ec2 = boto3.client("ec2", region_name=region)
            await self._check_security_groups(region)
            await self._check_ebs_encryption(region)
            await self._check_default_vpc(region)
            await self._check_imdsv2(region)
            await self._check_public_amis(region)

        return self.build_result(duration=time.time() - start)

    async def _check_security_groups(self, region: str) -> None:
        """CIS 5.2/5.3 — No unrestricted inbound 0.0.0.0/0 on SSH/RDP."""
        DANGEROUS_PORTS = {22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB"}
        try:
            paginator = self.ec2.get_paginator("describe_security_groups")
            for page in paginator.paginate():
                for sg in page["SecurityGroups"]:
                    self.resources_scanned += 1
                    for rule in sg.get("IpPermissions", []):
                        from_port = rule.get("FromPort", 0)
                        to_port = rule.get("ToPort", 65535)

                        for cidr in rule.get("IpRanges", []):
                            if cidr.get("CidrIp") in ("0.0.0.0/0", "::/0"):
                                # Check if covers dangerous ports
                                for port, service_name in DANGEROUS_PORTS.items():
                                    if from_port <= port <= to_port:
                                        self.add_finding(ScanFinding(
                                            rule_id=f"CIS-EC2-5.{2 if port == 22 else 3}",
                                            rule_name=f"Security group allows unrestricted {service_name} access from 0.0.0.0/0",
                                            severity="critical" if port in (22, 3389) else "high",
                                            resource_id=sg["GroupId"],
                                            resource_name=sg.get("GroupName", ""),
                                            resource_type="ec2:security_group",
                                            cloud_provider="aws",
                                            region=region,
                                            evidence={"port": port, "cidr": cidr.get("CidrIp"), "sg_name": sg.get("GroupName")},
                                            cvss_score=9.8,
                                            cis_benchmark_refs=[f"CIS AWS 5.{2 if port == 22 else 3}"],
                                            mitre_attack_techniques=["T1190", "T1021"],
                                            remediation_steps=f"Restrict inbound {service_name} (port {port}) to specific IP ranges.",
                                            remediation_code=f"aws ec2 revoke-security-group-ingress --region {region} --group-id {sg['GroupId']} --protocol tcp --port {port} --cidr 0.0.0.0/0",
                                        ))

                                # All traffic open
                                if rule.get("IpProtocol") == "-1":
                                    self.add_finding(ScanFinding(
                                        rule_id="EC2-SG-001",
                                        rule_name="Security group allows all inbound traffic from 0.0.0.0/0",
                                        severity="critical",
                                        resource_id=sg["GroupId"],
                                        resource_name=sg.get("GroupName", ""),
                                        resource_type="ec2:security_group",
                                        cloud_provider="aws",
                                        region=region,
                                        evidence={"cidr": cidr.get("CidrIp"), "sg_name": sg.get("GroupName")},
                                        cvss_score=10.0,
                                        mitre_attack_techniques=["T1190"],
                                        remediation_steps="Remove all-traffic inbound rules. Apply least-privilege security group rules.",
                                    ))
        except ClientError as exc:
            self.add_error(f"Security groups [{region}]: {exc}")

    async def _check_ebs_encryption(self, region: str) -> None:
        """CIS 2.2.1 — EBS volumes should be encrypted."""
        try:
            # Check default encryption setting
            enc_default = self.ec2.get_ebs_encryption_by_default()
            if not enc_default.get("EbsEncryptionByDefault", False):
                self.add_finding(ScanFinding(
                    rule_id="CIS-EC2-2.2.1",
                    rule_name="EBS encryption by default is not enabled",
                    severity="high",
                    resource_id=f"ec2:ebs-encryption-default:{region}",
                    resource_type="ec2:ebs_default_encryption",
                    cloud_provider="aws",
                    region=region,
                    cvss_score=7.0,
                    cis_benchmark_refs=["CIS AWS 2.2.1"],
                    remediation_steps=f"Enable EBS encryption by default in region {region}.",
                    remediation_code=f"aws ec2 enable-ebs-encryption-by-default --region {region}",
                ))

            # Check individual unencrypted volumes
            paginator = self.ec2.get_paginator("describe_volumes")
            for page in paginator.paginate():
                for vol in page["Volumes"]:
                    self.resources_scanned += 1
                    if not vol.get("Encrypted", False):
                        self.add_finding(ScanFinding(
                            rule_id="EC2-EBS-001",
                            rule_name="EBS volume is not encrypted",
                            severity="medium",
                            resource_id=vol["VolumeId"],
                            resource_type="ec2:ebs_volume",
                            cloud_provider="aws",
                            region=region,
                            evidence={"volume_type": vol.get("VolumeType"), "size_gb": vol.get("Size")},
                            cvss_score=5.5,
                            mitre_attack_techniques=["T1005"],
                            remediation_steps=f"Encrypt EBS volume {vol['VolumeId']} using a KMS key.",
                        ))
        except ClientError as exc:
            self.add_error(f"EBS encryption [{region}]: {exc}")

    async def _check_default_vpc(self, region: str) -> None:
        """CIS 5.4 — Ensure default VPC is not used."""
        try:
            vpcs = self.ec2.describe_vpcs(Filters=[{"Name": "isDefault", "Values": ["true"]}])
            for vpc in vpcs.get("Vpcs", []):
                self.resources_scanned += 1
                # Check if default VPC has instances
                instances = self.ec2.describe_instances(
                    Filters=[{"Name": "vpc-id", "Values": [vpc["VpcId"]]}]
                )
                instance_count = sum(
                    len(r["Instances"]) for r in instances.get("Reservations", [])
                )
                if instance_count > 0:
                    self.add_finding(ScanFinding(
                        rule_id="CIS-EC2-5.4",
                        rule_name="EC2 instances running in default VPC",
                        severity="medium",
                        resource_id=vpc["VpcId"],
                        resource_type="ec2:vpc",
                        cloud_provider="aws",
                        region=region,
                        evidence={"vpc_id": vpc["VpcId"], "instance_count": instance_count},
                        cvss_score=5.0,
                        cis_benchmark_refs=["CIS AWS 5.4"],
                        remediation_steps="Create a custom VPC and migrate instances away from the default VPC.",
                    ))
        except ClientError as exc:
            self.add_error(f"Default VPC check [{region}]: {exc}")

    async def _check_imdsv2(self, region: str) -> None:
        """EC2 IMDSv2 — Require instance metadata service v2."""
        try:
            paginator = self.ec2.get_paginator("describe_instances")
            for page in paginator.paginate():
                for reservation in page["Reservations"]:
                    for instance in reservation["Instances"]:
                        if instance["State"]["Name"] not in ("running", "stopped"):
                            continue
                        self.resources_scanned += 1
                        metadata_opts = instance.get("MetadataOptions", {})
                        if metadata_opts.get("HttpTokens") != "required":
                            self.add_finding(ScanFinding(
                                rule_id="EC2-IMDS-001",
                                rule_name="EC2 instance does not enforce IMDSv2",
                                severity="high",
                                resource_id=instance["InstanceId"],
                                resource_type="ec2:instance",
                                cloud_provider="aws",
                                region=region,
                                evidence={
                                    "instance_type": instance.get("InstanceType"),
                                    "http_tokens": metadata_opts.get("HttpTokens"),
                                },
                                cvss_score=7.5,
                                mitre_attack_techniques=["T1552.005"],
                                remediation_steps=f"Enforce IMDSv2 on instance {instance['InstanceId']} to prevent SSRF attacks.",
                                remediation_code=f"aws ec2 modify-instance-metadata-options --instance-id {instance['InstanceId']} --region {region} --http-tokens required --http-endpoint enabled",
                            ))
        except ClientError as exc:
            self.add_error(f"IMDSv2 check [{region}]: {exc}")

    async def _check_public_amis(self, region: str) -> None:
        """Check for publicly shared AMIs."""
        try:
            import boto3
            sts = boto3.client("sts")
            account_id = sts.get_caller_identity()["Account"]
            images = self.ec2.describe_images(Owners=[account_id], Filters=[{"Name": "is-public", "Values": ["true"]}])
            for image in images.get("Images", []):
                self.add_finding(ScanFinding(
                    rule_id="EC2-AMI-001",
                    rule_name="AMI is publicly shared",
                    severity="high",
                    resource_id=image["ImageId"],
                    resource_name=image.get("Name", ""),
                    resource_type="ec2:ami",
                    cloud_provider="aws",
                    region=region,
                    evidence={"name": image.get("Name"), "description": image.get("Description")},
                    cvss_score=7.0,
                    mitre_attack_techniques=["T1578"],
                    remediation_steps=f"Make AMI {image['ImageId']} private unless intentionally public.",
                    remediation_code=f"aws ec2 modify-image-attribute --image-id {image['ImageId']} --region {region} --launch-permission '{{\"Remove\":[{{\"Group\":\"all\"}}]}}'",
                ))
        except ClientError as exc:
            self.add_error(f"Public AMI check [{region}]: {exc}")
