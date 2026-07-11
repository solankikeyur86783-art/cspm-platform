import time
from typing import Any, Dict, List

import boto3
from botocore.exceptions import ClientError

from app.scanners.base import BaseScanner, ScanFinding, ScannerResult
from app.core.logging import logger


class AWSRDSScanner(BaseScanner):
    provider = "aws"
    service = "rds"

    def __init__(self, account_config: Dict[str, Any]):
        super().__init__(account_config)
        self.regions: List[str] = account_config.get("aws_regions") or ["us-east-1"]

    async def scan(self) -> ScannerResult:
        start = time.time()
        logger.info(f"Starting AWS RDS scan across regions: {self.regions}")

        for region in self.regions:
            self.rds = boto3.client("rds", region_name=region)
            await self._check_instances(region)
            await self._check_snapshots(region)
            await self._check_clusters(region)

        return self.build_result(duration=time.time() - start)

    async def _check_instances(self, region: str) -> None:
        try:
            paginator = self.rds.get_paginator("describe_db_instances")
            for page in paginator.paginate():
                for db in page["DBInstances"]:
                    self.resources_scanned += 1
                    db_id = db["DBInstanceIdentifier"]
                    arn = db["DBInstanceArn"]

                    # Public accessibility
                    if db.get("PubliclyAccessible"):
                        self.add_finding(ScanFinding(
                            rule_id="CIS-RDS-2.3.2",
                            rule_name="RDS instance is publicly accessible",
                            severity="critical",
                            resource_id=arn,
                            resource_name=db_id,
                            resource_type="rds:instance",
                            cloud_provider="aws",
                            region=region,
                            evidence={"engine": db.get("Engine"), "endpoint": db.get("Endpoint", {}).get("Address")},
                            cvss_score=9.8,
                            cis_benchmark_refs=["CIS AWS 2.3.2"],
                            mitre_attack_techniques=["T1190"],
                            remediation_steps=f"Disable public accessibility on RDS instance {db_id}.",
                            remediation_code=f"aws rds modify-db-instance --db-instance-identifier {db_id} --no-publicly-accessible --region {region}",
                        ))

                    # Encryption at rest
                    if not db.get("StorageEncrypted"):
                        self.add_finding(ScanFinding(
                            rule_id="CIS-RDS-2.3.1",
                            rule_name="RDS instance storage is not encrypted",
                            severity="high",
                            resource_id=arn,
                            resource_name=db_id,
                            resource_type="rds:instance",
                            cloud_provider="aws",
                            region=region,
                            evidence={"engine": db.get("Engine"), "size_gb": db.get("AllocatedStorage")},
                            cvss_score=7.5,
                            cis_benchmark_refs=["CIS AWS 2.3.1"],
                            mitre_attack_techniques=["T1005"],
                            remediation_steps=f"Enable encryption for RDS instance {db_id}. Note: requires snapshot + restore.",
                            remediation_code=f"# Snapshot → copy with encryption → restore\naws rds create-db-snapshot --db-instance-identifier {db_id} --db-snapshot-identifier {db_id}-encrypted-snap --region {region}",
                        ))

                    # Automated backups
                    if db.get("BackupRetentionPeriod", 0) < 7:
                        self.add_finding(ScanFinding(
                            rule_id="RDS-BACKUP-001",
                            rule_name="RDS automated backup retention is less than 7 days",
                            severity="medium",
                            resource_id=arn,
                            resource_name=db_id,
                            resource_type="rds:instance",
                            cloud_provider="aws",
                            region=region,
                            evidence={"retention_days": db.get("BackupRetentionPeriod")},
                            cvss_score=4.5,
                            remediation_steps=f"Set backup retention to at least 7 days on {db_id}.",
                            remediation_code=f"aws rds modify-db-instance --db-instance-identifier {db_id} --backup-retention-period 7 --region {region}",
                        ))

                    # Deletion protection
                    if not db.get("DeletionProtection"):
                        self.add_finding(ScanFinding(
                            rule_id="RDS-DEL-001",
                            rule_name="RDS instance does not have deletion protection enabled",
                            severity="medium",
                            resource_id=arn,
                            resource_name=db_id,
                            resource_type="rds:instance",
                            cloud_provider="aws",
                            region=region,
                            cvss_score=4.0,
                            remediation_steps=f"Enable deletion protection on {db_id}.",
                            remediation_code=f"aws rds modify-db-instance --db-instance-identifier {db_id} --deletion-protection --region {region}",
                        ))

                    # Multi-AZ for production
                    if not db.get("MultiAZ") and db.get("DBInstanceClass", "").startswith("db.r"):
                        self.add_finding(ScanFinding(
                            rule_id="RDS-HA-001",
                            rule_name="Production-class RDS instance not configured for Multi-AZ",
                            severity="medium",
                            resource_id=arn,
                            resource_name=db_id,
                            resource_type="rds:instance",
                            cloud_provider="aws",
                            region=region,
                            evidence={"instance_class": db.get("DBInstanceClass")},
                            cvss_score=4.0,
                            remediation_steps=f"Enable Multi-AZ for {db_id} to improve availability.",
                            remediation_code=f"aws rds modify-db-instance --db-instance-identifier {db_id} --multi-az --region {region}",
                        ))

                    # Minor version auto-upgrade
                    if not db.get("AutoMinorVersionUpgrade"):
                        self.add_finding(ScanFinding(
                            rule_id="RDS-PATCH-001",
                            rule_name="RDS instance auto minor version upgrade is disabled",
                            severity="low",
                            resource_id=arn,
                            resource_name=db_id,
                            resource_type="rds:instance",
                            cloud_provider="aws",
                            region=region,
                            cvss_score=3.0,
                            remediation_steps=f"Enable auto minor version upgrade on {db_id}.",
                            remediation_code=f"aws rds modify-db-instance --db-instance-identifier {db_id} --auto-minor-version-upgrade --region {region}",
                        ))

                    # Enhanced monitoring
                    if not db.get("MonitoringInterval", 0):
                        self.add_finding(ScanFinding(
                            rule_id="RDS-MON-001",
                            rule_name="RDS enhanced monitoring is not enabled",
                            severity="low",
                            resource_id=arn,
                            resource_name=db_id,
                            resource_type="rds:instance",
                            cloud_provider="aws",
                            region=region,
                            cvss_score=2.5,
                            remediation_steps=f"Enable enhanced monitoring on {db_id} with 60-second granularity.",
                        ))

        except ClientError as exc:
            self.add_error(f"RDS instances [{region}]: {exc}")

    async def _check_snapshots(self, region: str) -> None:
        """Check for publicly shared RDS snapshots."""
        try:
            paginator = self.rds.get_paginator("describe_db_snapshots")
            for page in paginator.paginate():
                for snap in page["DBSnapshots"]:
                    self.resources_scanned += 1
                    if snap.get("Encrypted") is False:
                        self.add_finding(ScanFinding(
                            rule_id="CIS-RDS-2.3.1-SNAP",
                            rule_name="RDS snapshot is not encrypted",
                            severity="high",
                            resource_id=snap["DBSnapshotArn"],
                            resource_name=snap["DBSnapshotIdentifier"],
                            resource_type="rds:snapshot",
                            cloud_provider="aws",
                            region=region,
                            cvss_score=7.0,
                            cis_benchmark_refs=["CIS AWS 2.3.1"],
                            mitre_attack_techniques=["T1005"],
                            remediation_steps=f"Copy snapshot {snap['DBSnapshotIdentifier']} with encryption enabled.",
                        ))

                    # Check if public
                    try:
                        attrs = self.rds.describe_db_snapshot_attributes(
                            DBSnapshotIdentifier=snap["DBSnapshotIdentifier"]
                        )
                        for attr in attrs.get("DBSnapshotAttributesResult", {}).get("DBSnapshotAttributes", []):
                            if attr["AttributeName"] == "restore" and "all" in attr.get("AttributeValues", []):
                                self.add_finding(ScanFinding(
                                    rule_id="RDS-SNAP-001",
                                    rule_name="RDS snapshot is publicly restorable",
                                    severity="critical",
                                    resource_id=snap["DBSnapshotArn"],
                                    resource_name=snap["DBSnapshotIdentifier"],
                                    resource_type="rds:snapshot",
                                    cloud_provider="aws",
                                    region=region,
                                    cvss_score=9.5,
                                    mitre_attack_techniques=["T1530"],
                                    remediation_steps=f"Remove public access from snapshot {snap['DBSnapshotIdentifier']}.",
                                    remediation_code=f"aws rds modify-db-snapshot-attribute --db-snapshot-identifier {snap['DBSnapshotIdentifier']} --attribute-name restore --values-to-remove all --region {region}",
                                ))
                    except ClientError:
                        pass

        except ClientError as exc:
            self.add_error(f"RDS snapshots [{region}]: {exc}")

    async def _check_clusters(self, region: str) -> None:
        """Check Aurora clusters."""
        try:
            paginator = self.rds.get_paginator("describe_db_clusters")
            for page in paginator.paginate():
                for cluster in page["DBClusters"]:
                    self.resources_scanned += 1
                    cluster_id = cluster["DBClusterIdentifier"]

                    if not cluster.get("StorageEncrypted"):
                        self.add_finding(ScanFinding(
                            rule_id="RDS-CLUSTER-ENC-001",
                            rule_name="Aurora cluster storage is not encrypted",
                            severity="high",
                            resource_id=cluster["DBClusterArn"],
                            resource_name=cluster_id,
                            resource_type="rds:cluster",
                            cloud_provider="aws",
                            region=region,
                            cvss_score=7.5,
                            remediation_steps=f"Enable encryption for Aurora cluster {cluster_id}.",
                        ))

                    if cluster.get("BackupRetentionPeriod", 0) < 7:
                        self.add_finding(ScanFinding(
                            rule_id="RDS-CLUSTER-BACKUP-001",
                            rule_name="Aurora cluster backup retention less than 7 days",
                            severity="medium",
                            resource_id=cluster["DBClusterArn"],
                            resource_name=cluster_id,
                            resource_type="rds:cluster",
                            cloud_provider="aws",
                            region=region,
                            evidence={"retention_days": cluster.get("BackupRetentionPeriod")},
                            cvss_score=4.5,
                            remediation_steps=f"Increase backup retention on cluster {cluster_id} to 7+ days.",
                        ))

        except ClientError as exc:
            self.add_error(f"RDS clusters [{region}]: {exc}")
