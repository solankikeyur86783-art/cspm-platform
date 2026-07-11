from app.scanners.azure.storage import AzureStorageScanner
from app.scanners.azure.iam import AzureIAMScanner
from app.scanners.azure.network import AzureNetworkScanner

AZURE_SCANNERS = [AzureStorageScanner, AzureIAMScanner, AzureNetworkScanner]

__all__ = ["AzureStorageScanner", "AzureIAMScanner", "AzureNetworkScanner", "AZURE_SCANNERS"]
