import pytest
from app.rules.compliance_mapper import (
    calculate_risk_score,
    map_to_compliance_frameworks,
    calculate_compliance_posture,
    severity_from_cvss,
    FRAMEWORK_CONTROLS,
)
from app.scanners.base import ScanFinding


def _make_finding(rule_id: str, severity: str, cvss: float = 5.0) -> ScanFinding:
    return ScanFinding(
        rule_id=rule_id,
        rule_name=f"Test rule {rule_id}",
        severity=severity,
        resource_id="test-resource",
        resource_type="test:resource",
        cloud_provider="aws",
        cvss_score=cvss,
    )


def test_risk_score_empty():
    assert calculate_risk_score([]) == 0.0


def test_risk_score_increases_with_more_findings():
    few = [_make_finding("X", "high") for _ in range(3)]
    many = [_make_finding("X", "high") for _ in range(20)]
    assert calculate_risk_score(many) > calculate_risk_score(few)


def test_risk_score_critical_higher_than_low():
    criticals = [_make_finding("X", "critical") for _ in range(5)]
    lows = [_make_finding("X", "low") for _ in range(5)]
    assert calculate_risk_score(criticals) > calculate_risk_score(lows)


def test_risk_score_max_100():
    huge = [_make_finding("X", "critical") for _ in range(1000)]
    score = calculate_risk_score(huge)
    assert score <= 100.0


def test_severity_from_cvss():
    assert severity_from_cvss(9.5) == "critical"
    assert severity_from_cvss(7.5) == "high"
    assert severity_from_cvss(5.0) == "medium"
    assert severity_from_cvss(3.0) == "low"
    assert severity_from_cvss(0.5) == "info"


def test_map_to_compliance_frameworks_iam():
    frameworks = map_to_compliance_frameworks("CIS-IAM-1.1")
    assert len(frameworks) > 0
    assert any("CIS AWS" in f for f in frameworks)


def test_map_to_compliance_frameworks_unknown():
    frameworks = map_to_compliance_frameworks("UNKNOWN-RULE-999")
    assert frameworks == []


def test_compliance_posture_clean():
    posture = calculate_compliance_posture([])
    for fw, data in posture.items():
        assert data["score_percent"] == 100.0
        assert data["failing"] == 0


def test_compliance_posture_with_iam_failures():
    findings = [
        type("F", (), {"rule_id": "CIS-IAM-1.1", "severity": "critical"})(),
        type("F", (), {"rule_id": "CIS-IAM-1.14", "severity": "high"})(),
    ]
    posture = calculate_compliance_posture(findings)
    cis_aws = posture.get("CIS AWS", {})
    assert cis_aws.get("failing", 0) > 0
    assert cis_aws.get("score_percent", 100) < 100


def test_all_frameworks_defined():
    assert "CIS AWS" in FRAMEWORK_CONTROLS
    assert "CIS GCP" in FRAMEWORK_CONTROLS
    assert "CIS Azure" in FRAMEWORK_CONTROLS
    assert "SOC 2" in FRAMEWORK_CONTROLS
    assert "HIPAA" in FRAMEWORK_CONTROLS
