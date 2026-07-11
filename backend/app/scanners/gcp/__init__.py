from app.scanners.gcp.iam import GCPIAMScanner
from app.scanners.gcp.storage import GCPStorageScanner
from app.scanners.gcp.compute import GCPComputeScanner

GCP_SCANNERS = [GCPIAMScanner, GCPStorageScanner, GCPComputeScanner]

__all__ = ["GCPIAMScanner", "GCPStorageScanner", "GCPComputeScanner", "GCP_SCANNERS"]
