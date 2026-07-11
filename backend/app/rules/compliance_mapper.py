from typing import List, Dict, Any, Optional
from app.scanners.base import ScanFinding


# ── CVSS Scoring ─────────────────────────────────────────────────────────────

SEVERITY_TO_CVSS = {
    "critical": 9.5,
    "high": 7.5,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}

CVSS_TO_SEVERITY = [
    (9.0, "critical"),
    (7.0, "high"),
    (4.0, "medium"),
    (1.0, "low"),
    (0.0, "info"),
]


def severity_from_cvss(score: float) -> str:
    for threshold, label in CVSS_TO_SEVERITY:
        if score >= threshold:
            return label
    return "info"


def enrich_cvss(finding: ScanFinding) -> ScanFinding:
    """Ensure every finding has a CVSS score."""
    if not finding.cvss_score:
        finding.cvss_score = SEVERITY_TO_CVSS.get(finding.severity, 5.0)
    return finding


# ── Risk Score Calculator ─────────────────────────────────────────────────────

SEVERITY_WEIGHTS = {
    "critical": 10,
    "high": 7,
    "medium": 4,
    "low": 1,
    "info": 0,
}


def calculate_risk_score(findings: List[ScanFinding]) -> float:
    """
    Calculate an overall risk score (0-100) for a set of findings.
    Higher = more risk. Uses weighted sum with diminishing returns.
    """
    if not findings:
        return 0.0

    total_weight = sum(SEVERITY_WEIGHTS.get(f.severity, 0) for f in findings)

    # Cap at 100 using logarithmic scale
    import math
    raw = min(total_weight, 500)
    score = (math.log1p(raw) / math.log1p(500)) * 100
    return round(score, 1)


# ── Compliance Mapper ─────────────────────────────────────────────────────────

FRAMEWORK_CONTROLS: Dict[str, Dict[str, List[str]]] = {
    "CIS AWS": {
        "1.x - Identity and Access Management": ["CIS-IAM"],
        "2.x - Storage": ["CIS-S3", "CIS-RDS", "CIS-EC2-2"],
        "3.x - Logging": ["CIS-CT", "CIS-CW"],
        "4.x - Monitoring": ["CIS-CW"],
        "5.x - Networking": ["CIS-EC2-5", "CIS-VPC"],
    },
    "CIS GCP": {
        "1.x - IAM": ["CIS-GCP-IAM"],
        "5.x - Storage": ["CIS-GCS"],
    },
    "CIS Azure": {
        "3.x - Storage": ["CIS-AZ"],
    },
    "SOC 2": {
        "CC6 - Logical Access": ["CIS-IAM", "CIS-GCP-IAM", "CIS-AZ"],
        "CC7 - System Operations": ["CIS-CT", "CIS-CW"],
        "CC8 - Change Management": ["RDS-PATCH", "EC2-IMDS"],
    },
    "HIPAA": {
        "164.312(a)(1) - Access Control": ["CIS-IAM", "CIS-GCP-IAM"],
        "164.312(b) - Audit Controls": ["CIS-CT", "CIS-CW"],
        "164.312(a)(2)(iv) - Encryption": ["CIS-S3", "CIS-RDS", "EC2-EBS"],
    },
}


def map_to_compliance_frameworks(rule_id: str) -> List[str]:
    """Return which compliance frameworks a rule_id maps to."""
    frameworks = []
    for framework, controls in FRAMEWORK_CONTROLS.items():
        for control, prefixes in controls.items():
            if any(rule_id.startswith(p) for p in prefixes):
                frameworks.append(f"{framework} — {control}")
    return frameworks


def calculate_compliance_posture(findings: List) -> Dict[str, Any]:
    """
    Calculate compliance posture per framework.
    Returns percentage of controls with no open findings.
    """
    framework_hits: Dict[str, set] = {}

    for finding in findings:
        rule_id = finding.rule_id if hasattr(finding, "rule_id") else finding.get("rule_id", "")
        for framework, controls in FRAMEWORK_CONTROLS.items():
            for control, prefixes in controls.items():
                if any(rule_id.startswith(p) for p in prefixes):
                    framework_hits.setdefault(framework, set()).add(control)

    result = {}
    for framework, controls in FRAMEWORK_CONTROLS.items():
        total = len(controls)
        failed = len(framework_hits.get(framework, set()))
        passing = max(0, total - failed)
        result[framework] = {
            "total_controls": total,
            "passing": passing,
            "failing": failed,
            "score_percent": round((passing / total) * 100, 1) if total else 100.0,
        }

    return result
