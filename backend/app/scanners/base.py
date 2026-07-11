from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
from datetime import datetime, timezone

from app.core.logging import logger


@dataclass
class ScanFinding:
    rule_id: str
    rule_name: str
    severity: str
    resource_id: str
    resource_type: str
    cloud_provider: str
    rule_description: str = ""
    resource_name: str = ""
    resource_arn: str = ""
    region: str = ""
    evidence: Dict[str, Any] = field(default_factory=dict)
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cis_benchmark_refs: List[str] = field(default_factory=list)
    mitre_attack_techniques: List[str] = field(default_factory=list)
    compliance_frameworks: List[str] = field(default_factory=list)
    remediation_steps: str = ""
    remediation_code: str = ""


@dataclass
class ScannerResult:
    provider: str
    service: str
    findings: List[ScanFinding] = field(default_factory=list)
    resources_scanned: int = 0
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    scanned_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


class BaseScanner(ABC):
    provider: str = "unknown"
    service: str = "unknown"

    def __init__(self, account_config: Dict[str, Any]):
        self.account_config = account_config
        self.findings: List[ScanFinding] = []
        self.resources_scanned = 0
        self.errors: List[str] = []

    @abstractmethod
    async def scan(self) -> ScannerResult:
        """Run the scanner and return results."""
        ...

    def add_finding(self, finding: ScanFinding) -> None:
        self.findings.append(finding)
        logger.debug(f"[{self.provider}/{self.service}] Finding: {finding.rule_id} | {finding.severity} | {finding.resource_id}")

    def add_error(self, msg: str) -> None:
        self.errors.append(msg)
        logger.warning(f"[{self.provider}/{self.service}] Error: {msg}")

    def build_result(self, duration: float = 0.0) -> ScannerResult:
        return ScannerResult(
            provider=self.provider,
            service=self.service,
            findings=self.findings,
            resources_scanned=self.resources_scanned,
            errors=self.errors,
            duration_seconds=duration,
        )
