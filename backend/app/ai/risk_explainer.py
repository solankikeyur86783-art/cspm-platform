from typing import Dict, Any
from app.ai.groq_client import GroqClient
from app.scanners.base import ScanFinding


SYSTEM_PROMPT = """You are a senior cloud security engineer at a Fortune 500 company.
You explain security findings clearly to both technical teams and executives.
You provide concise, actionable, and accurate information.
Always respond in valid JSON."""


class RiskExplainer:
    def __init__(self, client: GroqClient):
        self.client = client

    async def explain(self, finding: ScanFinding) -> Dict[str, Any]:
        """
        Generate AI explanation and remediation for a finding.
        Returns dict with 'explanation' and 'remediation' keys.
        """
        user_prompt = f"""Analyze this cloud security finding and provide a response:

Rule ID: {finding.rule_id}
Rule Name: {finding.rule_name}
Severity: {finding.severity.upper()}
CVSS Score: {finding.cvss_score}
Cloud Provider: {finding.cloud_provider.upper()}
Resource Type: {finding.resource_type}
Resource ID: {finding.resource_id}
Evidence: {finding.evidence}
MITRE ATT&CK Techniques: {', '.join(finding.mitre_attack_techniques) if finding.mitre_attack_techniques else 'N/A'}
CIS Benchmark Refs: {', '.join(finding.cis_benchmark_refs) if finding.cis_benchmark_refs else 'N/A'}

Respond with JSON:
{{
  "explanation": "2-3 sentence plain English explanation of the risk and business impact",
  "remediation": "Step-by-step remediation with CLI commands or console steps",
  "attack_scenario": "Brief description of how an attacker could exploit this",
  "priority": "immediate|high|medium|low"
}}"""

        return await self.client.complete_json(SYSTEM_PROMPT, user_prompt, max_tokens=600)

    async def generate_executive_summary(self, scan_stats: Dict[str, Any]) -> str:
        """Generate a plain-English executive summary for a completed scan."""
        user_prompt = f"""Write an executive summary for a cloud security scan:

Cloud Account: {scan_stats.get('account_name')}
Provider: {scan_stats.get('provider', '').upper()}
Scan Date: {scan_stats.get('scan_date')}
Risk Score: {scan_stats.get('risk_score')}/100
Resources Scanned: {scan_stats.get('resources_scanned')}
Total Findings: {scan_stats.get('total_findings')}
Critical: {scan_stats.get('critical_findings')}
High: {scan_stats.get('high_findings')}
Medium: {scan_stats.get('medium_findings')}
Low: {scan_stats.get('low_findings')}
Top Rules Triggered: {scan_stats.get('top_rules', [])}

Write a 3-4 paragraph executive summary suitable for C-suite readers.
Cover: overall posture, key risks, immediate actions needed, and positive findings."""

        return await self.client.complete(
            system_prompt="You are a CISO writing a board-level security report. Be concise, clear, and business-focused.",
            user_prompt=user_prompt,
            max_tokens=800,
            temperature=0.3,
        )
